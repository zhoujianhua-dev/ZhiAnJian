#!/bin/bash
# 智安鉴 + 内置扫描引擎 · 容器化部署脚本
# 用法：在仓库根目录执行 ./deploy.sh
set -e
cd /opt/zhianjian

# 两个配置文件都不入库：config.json 存 AI Key 与引擎账号，.env 存引擎密钥。
# 若文件缺失，Docker 会把挂载点建成同名目录，导致容器起不来，这里先兜底。
[ -f config.json ] || cp config.example.json config.json
[ -f scan-engine/backend/.env ] || cp scan-engine/backend/.env.example scan-engine/backend/.env
mkdir -p data

echo "=== BUILD ==="
date -u
docker compose build

echo "=== UP ==="
docker compose up -d
sleep 20
docker compose ps
echo "=== DONE ==="
date -u
