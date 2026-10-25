#!/bin/bash

API_BASE="http://localhost:8000/api/v1"

echo "=== 测试系统设置 API ==="
echo ""

echo "1. 获取系统设置"
curl -s "${API_BASE}/settings/system" | python3 -m json.tool
echo -e "\n"

echo "2. 更新扫描设置"
curl -s -X PUT "${API_BASE}/settings/system" \
  -H "Content-Type: application/json" \
  -d '{
    "search": {
      "enabled": true,
      "provider": "duckduckgo",
      "max_results": 5
    },
    "scan": {
      "max_concurrent_scans": 8,
      "scan_timeout": 7200,
      "rate_limit_per_target": 15,
      "scan_temp_dir": "/tmp/shelling_scans"
    }
  }' | python3 -m json.tool
echo -e "\n"

echo "3. 获取 LLM 配置列表"
curl -s "${API_BASE}/settings/llm" | python3 -m json.tool
echo -e "\n"

echo "=== 测试完成 ==="
