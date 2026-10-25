#!/bin/bash
set -x
cd /opt/shelling
echo "=== KALI REBUILD START $(date) ==="
docker compose build kali_scanner
echo "=== BUILD RC=$? $(date) ==="
docker compose up -d kali_scanner
echo "=== UP RC=$? $(date) ==="
sleep 15
docker compose ps kali_scanner
echo "=== DONE $(date) ==="
