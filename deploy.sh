#!/bin/bash
# 智安鉴 · 容器化部署脚本
set -x
cd /opt/zhianjian

# config.json 保存 AI Key 与 Shelling 账号密码，不入库；首次部署从模板生成。
# 若文件缺失，docker compose 会把挂载点建成同名目录，导致容器启动失败。
if [ ! -f config.json ]; then
    cp config.example.json config.json
    echo "config.json 不存在，已从 config.example.json 生成"
fi

echo "=== BUILD START $(date) ==="
docker compose build
echo "=== BUILD RC=$? $(date) ==="
docker compose up -d
echo "=== UP RC=$? $(date) ==="
sleep 12
docker compose ps
echo "=== DONE $(date) ==="
