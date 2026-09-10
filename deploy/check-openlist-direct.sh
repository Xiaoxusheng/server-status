#!/bin/bash
# 手记云直链可行性验收脚本（docs/private-notes-cloud-impl-spec.md §6）
# 用法: ./check-openlist-direct.sh <OpenList地址> <API Token> <云盘内某文件完整路径>
# 例:   ./check-openlist-direct.sh http://127.0.0.1:5244 xxxxxxx "/home/备份/手记媒体/2026/09/10/f_x.jpg"
# 判定:
#   1) fs/get 能否取到 raw_url（token / 路径 / 驱动是否直链模式）
#   2) 服务器视角直链可达性
#   3) CDN 是否带 CORS 头（决定浏览器能否 fetch 跨域密文，最关键）
#   4) 把 RAW_URL 拿到本地浏览器/curl 复测，检查是否绑定服务器 IP
# 任一不满足 → 线上自动全走回退（无带宽收益但无损害），无需改代码
set -euo pipefail
BASE="$1"; TOKEN="$2"; PATH_="$3"
echo "== 1) fs/get 获取直链 =="
RESP=$(curl -s -X POST "$BASE/api/fs/get" -H "Authorization: $TOKEN" -H "Content-Type: application/json" -d "{\"path\":\"$PATH_\"}")
echo "$RESP" | head -c 400; echo
RAW=$(echo "$RESP" | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"].get("raw_url",""))' 2>/dev/null || true)
[ -n "$RAW" ] || { echo "❌ 未取到 raw_url（token 错误 / 路径错误 / 驱动仅代理模式）"; exit 1; }
echo "== 2) 直链可达性（服务器视角） =="; curl -sI "$RAW" | head -5
echo "== 3) CORS 检查（决定浏览器能否 fetch 跨域密文，最关键） =="
curl -sI -H "Origin: https://example.com" "$RAW" | grep -i "access-control-allow-origin" \
  && echo "✅ CDN 带 CORS 头，直链方案可用" || echo "⚠️ 无 CORS 头：浏览器 fetch 会失败并自动回退服务器（带宽不省但功能无损）"
echo "== 4) 把 RAW_URL 换到你本地浏览器/curl 再测一次，检查是否绑定服务器 IP =="
echo "RAW_URL=$RAW"
