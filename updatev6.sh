#!/bin/bash
set -e

# ---------------- 配置区 ----------------
ZONE_ID=""
AUTH="Authorization: Bearer "
API="https/api.cloudflare.com/client/v4"

CFDATA_CMD="./cfdata"   # cfdata 可执行文件路径
SCAN_NUM=100
IP_NUM=2
IP_VERSION=6
SLEEP_SECONDS=30       # 两次执行间隔
# --------------------------------------

# 定义数据中心和对应域名
declare -A DC_DOMAIN
DC_DOMAIN=( ["HKG"]=".xyz" ["SIN"]="xyz" )

ITER=0
# 循环处理每个数据中心
for DC in "${!DC_DOMAIN[@]}"; do
    DOMAIN="${DC_DOMAIN[$DC]}"
    ITER=$((ITER+1))
    echo "==== 生成 $DC 的 IP 列表并更新 $DOMAIN ===="

    # 1. 执行 cfdata 生成 ip.txt
    $CFDATA_CMD -scan "$SCAN_NUM" -ips "$IP_VERSION" -colo "$DC" -ipnum "$IP_NUM"

    IP_FILE="ip.txt"
    if [ ! -f "$IP_FILE" ]; then
        echo "错误: $IP_FILE 不存在，程序退出"
        exit 1
    fi

    # 2. 删除旧 AAAA 记录
    record_ids=$(curl -s -X GET "$API/zones/$ZONE_ID/dns_records?type=AAAA&name=$DOMAIN" \
        -H "$AUTH" -H "Content-Type: application/json" | jq -r '.result[].id')

    if [ -n "$record_ids" ]; then
        for id in $record_ids; do
            echo "删除旧记录 ID: $id"
            curl -s -X DELETE "$API/zones/$ZONE_ID/dns_records/$id" \
                -H "$AUTH" -H "Content-Type: application/json" -o /dev/null
        done
    else
        echo "没有需要删除的旧 AAAA 记录"
    fi

    # 3. 添加新 AAAA 记录（只取第一列）
    ip_list=$(awk -F',' '{print $1}' "$IP_FILE" | sed '/^\s*$/d')

    for ip in $ip_list; do
        if [ -n "$ip" ]; then
            echo "添加新记录: $ip"
            curl -s -X POST "$API/zones/$ZONE_ID/dns_records" \
                -H "Content-Type: application/json" \
                -H "$AUTH" \
                -d "{\"type\":\"AAAA\",\"name\":\"$DOMAIN\",\"content\":\"$ip\",\"ttl\":120,\"proxied\":false}" \
                | jq -r '.success'
        fi
    done

    echo "==== $DOMAIN 更新完成 ===="

    # 第一次执行后 sleep
    if [ $ITER -eq 1 ]; then
        echo "等待 $SLEEP_SECONDS 秒后执行下一个数据中心..."
        sleep $SLEEP_SECONDS
    fi
done

echo "==== 所有数据中心 IP 更新完成 ===="
