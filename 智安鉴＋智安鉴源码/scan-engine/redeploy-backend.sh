#!/bin/bash
set -x
cd /opt/shelling
echo "=== REBUILD START $(date) ==="
docker compose build backend celery_worker
echo "=== BUILD RC=$? $(date) ==="
docker compose up -d backend celery_worker
echo "=== UP RC=$? $(date) ==="
sleep 20
docker compose ps
echo "=== DONE $(date) ==="
