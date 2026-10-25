#!/bin/bash
set -x
cd /opt/shelling
echo "=== BUILD START $(date) ==="
docker compose build --progress=plain
echo "=== BUILD RC=$? $(date) ==="
docker compose up -d
echo "=== UP RC=$? $(date) ==="
docker compose ps
echo "=== DEPLOY DONE $(date) ==="
