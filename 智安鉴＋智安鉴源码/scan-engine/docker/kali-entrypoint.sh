#!/bin/bash
set -e

echo "🚀 Kali Scanner Container Starting..."

# 更新 Nuclei 模板
echo "📦 Updating Nuclei templates from GitHub..."
(
    nuclei -update-templates -silent 2>/dev/null || echo "⚠️  Nuclei templates update failed (using cached version)"
) &

# 初始化 Metasploit 数据库
if [ ! -f /root/.msf4/database.yml ]; then
    echo "🗄️  Initializing Metasploit database..."
    service postgresql start 2>/dev/null || true
    msfdb init 2>/dev/null || echo "⚠️  MSF database init failed"
    service postgresql stop 2>/dev/null || true
fi

echo "✅ Kali Scanner ready"

# 启动 API 服务
exec python3 /scanner/service/main.py
