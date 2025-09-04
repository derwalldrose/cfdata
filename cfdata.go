package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ----------------------- 数据类型定义 ----------------------- 

type ScanResult struct {
	IP          string
	DataCenter  string
	Region      string
	City        string
	LatencyStr  string
	TCPDuration time.Duration
}

type location struct {
	Iata   string  `json:"iata"`
	Lat    float64 `json:"lat"`
	Lon    float64 `json:"lon"`
	Cca2   string  `json:"cca2"`
	Region string  `json:"region"`
	City   string  `json:"city"`
}

// ----------------------- 主程序入口 ----------------------- 

func main() {
	// 定义命令行参数
	scanThreads := flag.Int("scan", 100, "扫描阶段最大并发数")
	colo := flag.String("colo", "", "筛选数据中心例如 HKG,SJC,LAX (多个数据中心用逗号隔开,留空则忽略匹配)")
	ipnum := flag.Int("ipnum", 20, "提取的有效IP数量")
	ips := flag.String("ips", "4", "指定生成IPv4还是IPv6地址 (4或6)")
	flag.Parse()

	ipType, err := strconv.Atoi(*ips)
	if err != nil || (ipType != 4 && ipType != 6) {
		fmt.Println("IP类型参数错误，必须是 4 或 6")
		return
	}

	// 运行IP扫描
	runIPScan(ipType, *scanThreads)

	// 从 ip.csv 中读取并根据参数筛选IP
	resultsList := filterIPsFromCSV(*colo, *ipnum)
	if len(resultsList) == 0 {
		fmt.Println("未找到符合条件的IP地址，程序退出。")
		return
	}

	// 将IP列表写入 ip.txt
	err = writeIPsToFile("ip.txt", resultsList)
	if err != nil {
		fmt.Println("写入 ip.txt 文件失败:", err)
	} else {
		fmt.Printf("已将 %d 个优选IP地址写入 ip.txt\n", len(resultsList))
	}

	fmt.Println("\n程序执行结束。")
}

// ----------------------- 功能模块 ----------------------- 

// runIPScan 根据用户选择的IPv4/IPv6，从指定URL获取CIDR列表、生成随机IP，然后扫描测试数据中心信息，最终写入 ip.csv
func runIPScan(ipType int, scanMaxThreads int) {
	var filename, url string
	if ipType == 6 {
		filename = "ips-v6.txt"
		url = "https://www.baipiao.eu.org/cloudflare/ips-v6"
	} else {
		filename = "ips-v4.txt"
		url = "https://www.baipiao.eu.org/cloudflare/ips-v4"
	}

	// 检查本地文件是否存在
	var content string
	var err error
	if _, err = os.Stat(filename); os.IsNotExist(err) {
		fmt.Printf("文件 %s 不存在，正在从 URL %s 下载数据\n", filename, url)
		content, err = getURLContent(url)
		if err != nil {
			fmt.Println("获取 URL 内容出错:", err)
			return
		}
		err = saveToFile(filename, content)
		if err != nil {
			fmt.Println("保存文件出错:", err)
			return
		}
	} else {
		content, err = getFileContent(filename)
		if err != nil {
			fmt.Println("读取本地文件出错:", err)
			return
		}
	}

	// 提取IP列表，并随机生成IP（每个子网取一个随机IP）
	ipList := parseIPList(content)
	if ipType == 6 {
		ipList = getRandomIPv6s(ipList)
	} else {
		ipList = getRandomIPv4s(ipList)
	}

	// 下载或读取 locations.json 文件以获取数据中心位置信息
	var locations []location
	if _, err := os.Stat("locations.json"); os.IsNotExist(err) {
		fmt.Println("本地 locations.json 不存在，正在从 https://speed.cloudflare.com/locations 下载")
		resp, err := http.Get("https://speed.cloudflare.com/locations")
		if err != nil {
			fmt.Printf("无法下载 locations.json: %v\n", err)
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("无法读取响应体: %v\n", err)
			return
		}
		err = json.Unmarshal(body, &locations)
		if err != nil {
			fmt.Printf("无法解析JSON: %v\n", err)
			return
		}
		err = saveToFile("locations.json", string(body))
		if err != nil {
			fmt.Printf("保存 locations.json 失败: %v\n", err)
			return
		}
	} else {
		fmt.Println("本地 locations.json 已存在，无需重新下载")
		file, err := os.Open("locations.json")
		if err != nil {
			fmt.Printf("无法打开 locations.json: %v\n", err)
			return
		}
		defer file.Close()
		body, err := io.ReadAll(file)
		if err != nil {
			fmt.Printf("读取 locations.json 失败: %v\n", err)
			return
		}
		err = json.Unmarshal(body, &locations)
		if err != nil {
			fmt.Printf("解析 locations.json 失败: %v\n", err)
			return
		}
	}

	// 构造 location 映射，key 为数据中心代码
	locationMap := make(map[string]location)
	for _, loc := range locations {
		locationMap[loc.Iata] = loc
	}

	// 并发测试每个IP，用于获取数据中心、城市和延迟信息
	var wg sync.WaitGroup
	wg.Add(len(ipList))
	resultChan := make(chan ScanResult, len(ipList))
	thread := make(chan struct{}, scanMaxThreads)
	var count int
	total := len(ipList)
	for _, ip := range ipList {
		thread <- struct{}{}
		go func(ip string) {
			defer func() {
				<-thread
				wg.Done()
				count++
				percentage := float64(count) / float64(total) * 100
				fmt.Printf("扫描进度: %d/%d (%.2f%%)\r", count, total, percentage)
				if count == total {
					fmt.Println("")
				}
			}()
			dialer := &net.Dialer{
				Timeout: 1 * time.Second,
			}
			start := time.Now()
			conn, err := dialer.Dial("tcp", net.JoinHostPort(ip, "80"))
			if err != nil {
				return
			}
			defer conn.Close()
			tcpDuration := time.Since(start)
			// 用自定义 http.Client 重用连接
			start = time.Now()
			client := http.Client{
				Transport: &http.Transport{
					Dial: func(network, addr string) (net.Conn, error) {
						return conn, nil
					},
				},
				Timeout: 1 * time.Second,
			}
			requestURL := "http://" + net.JoinHostPort(ip, "80") + "/cdn-cgi/trace"
			req, _ := http.NewRequest("GET", requestURL, nil)
			req.Header.Set("User-Agent", "Mozilla/5.0")
			req.Close = true
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			duration := time.Since(start)
			maxDuration := 2 * time.Second
			if duration > maxDuration {
				return
			}
			buf := &bytes.Buffer{}
			timeoutChan := time.After(maxDuration)
			done := make(chan bool)
			go func() {
					_, _ = io.Copy(buf, resp.Body)
					done <- true
				}()
			select {
			case <-done:
			case <-timeoutChan:
				return
			}
			bodyStr := buf.String()
			if strings.Contains(bodyStr, "uag=Mozilla/5.0") {
				regex := regexp.MustCompile(`colo=([A-Z]+)`)
				matches := regex.FindStringSubmatch(bodyStr)
				if len(matches) > 1 {
					dataCenter := matches[1]
					loc, ok := locationMap[dataCenter]
					if ok {
						fmt.Printf("有效IP: %s, %s, 延迟: %d ms\n", ip, loc.City, tcpDuration.Milliseconds())
						resultChan <- ScanResult{IP: ip, DataCenter: dataCenter, Region: loc.Region, City: loc.City, LatencyStr: fmt.Sprintf("%d ms", tcpDuration.Milliseconds()), TCPDuration: tcpDuration}
					} else {
						fmt.Printf("有效IP: %s, 数据中心: %s, 未知位置信息, 延迟: %d ms\n", ip, dataCenter, tcpDuration.Milliseconds())
						resultChan <- ScanResult{IP: ip, DataCenter: dataCenter, Region: "", City: "", LatencyStr: fmt.Sprintf("%d ms", tcpDuration.Milliseconds()), TCPDuration: tcpDuration}
					}
				}
			}
		}(ip)
	}
	wg.Wait()
	close(resultChan)

	// 如果没有有效IP，直接退出程序
	if len(resultChan) == 0 {
		fmt.Println("未发现有效IP，程序退出。")
		os.Exit(1)
	}

	var results []ScanResult
	for r := range resultChan {
		results = append(results, r)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].TCPDuration < results[j].TCPDuration
	})
	// 将扫描结果写入 ip.csv
	file, err := os.Create("ip.csv")
	if err != nil {
		fmt.Printf("无法创建 ip.csv 文件: %v\n", err)
		return
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	writer.Write([]string{"IP地址", "数据中心", "地区", "城市", "网络延迟"})
	for _, res := range results {
		writer.Write([]string{res.IP, res.DataCenter, res.Region, res.City, res.LatencyStr})
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		fmt.Printf("写入 ip.csv 失败: %v\n", err)
		return
	}
	fmt.Println("扫描完成，ip.csv生成成功。")
}

// filterIPsFromCSV 从 ip.csv 读取IP，根据colo进行筛选，并返回指定数量的IP
func filterIPsFromCSV(colo string, ipnum int) []string {
	file, err := os.Open("ip.csv")
	if err != nil {
		fmt.Println("无法打开 ip.csv:", err)
		return nil
	}
	defer file.Close()
	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		fmt.Println("读取 ip.csv 失败:", err)
		return nil
	}

	var selectedLines []string
	coloFilter := make(map[string]bool)
	if colo != "" {
		for _, c := range strings.Split(colo, ",") {
			coloFilter[strings.ToUpper(strings.TrimSpace(c))] = true
		}
	}

	// records[0] is the header, so we start from i=1
	for i, record := range records {
		if i == 0 {
			continue
		}
		if len(record) < 5 {
			continue
		}
		ip := record[0]
		dataCenter := record[1]
		latency := record[4]

		line := fmt.Sprintf("%s,%s,%s", ip, dataCenter, latency)

		if len(coloFilter) > 0 {
			if _, ok := coloFilter[dataCenter]; ok {
				selectedLines = append(selectedLines, line)
			}
		} else {
			selectedLines = append(selectedLines, line)
		}
	}

	if len(selectedLines) > ipnum {
		return selectedLines[:ipnum]
	}

	return selectedLines
}

// writeIPsToFile 将IP地址写入指定文本文件
func writeIPsToFile(filename string, lines []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	for _, line := range lines {
		_, err := file.WriteString(line + "\n")
		if err != nil {
			return err
		}
	}
	return nil
}

// ----------------------- 工具函数 ----------------------- 

// getURLContent 根据指定URL下载内容
func getURLContent(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP请求失败，状态码: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// getFileContent 从本地读取指定文件的内容
func getFileContent(filename string) (string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// saveToFile 将内容保存到指定文件中
func saveToFile(filename, content string) error {
	return os.WriteFile(filename, []byte(content), 0644)
}

// parseIPList 按行解析文本内容，返回非空行组成的字符串切片
func parseIPList(content string) []string {
	scanner := bufio.NewScanner(strings.NewReader(content))
	var ipList []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			ipList = append(ipList, line)
		}
	}
	return ipList
}

// getRandomIPv4s 从类似 "xxx.xxx.xxx.xxx/24" 的CIDR中随机生成一个IPv4地址（只替换最后一段）
func getRandomIPv4s(ipList []string) []string {
	rand.Seed(time.Now().UnixNano())
	var randomIPs []string
	for _, subnet := range ipList {
		baseIP := strings.TrimSuffix(subnet, "/24")
		octets := strings.Split(baseIP, ".")
		if len(octets) != 4 {
			continue
		}
		octets[3] = fmt.Sprintf("%d", rand.Intn(256))
		randomIP := strings.Join(octets, ".")
		randomIPs = append(randomIPs, randomIP)
	}
	return randomIPs
}

// getRandomIPv6s 从类似 "xxxx:xxxx:xxxx::/48" 的CIDR中随机生成一个IPv6地址（保留前三组）
func getRandomIPv6s(ipList []string) []string {
	rand.Seed(time.Now().UnixNano())
	var randomIPs []string
	for _, subnet := range ipList {
		baseIP := strings.TrimSuffix(subnet, "/48")
		sections := strings.Split(baseIP, ":")
		if len(sections) < 3 {
			continue
		}
		sections = sections[:3]
		// 生成后三组随机数据（使总组数达到8组）
		for i := 3; i < 8; i++ {
			sections = append(sections, fmt.Sprintf("%x", rand.Intn(65536)))
		}
		randomIP := strings.Join(sections, ":")
		randomIPs = append(randomIPs, randomIP)
	}
	return randomIPs
}
