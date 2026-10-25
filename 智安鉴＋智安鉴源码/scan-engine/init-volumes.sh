#!/bin/bash
# 为一体化编排准备引擎命名卷（external 卷不会被 compose 自动创建）。
# 新机器首次部署执行一次；本机已存在则跳过。
set -e
for v in docker_postgres_data docker_mongodb_data docker_redis_data docker_tools_data docker_kali_tools docker_kali_output docker_kali_logs docker_kali_tmp; do
    docker volume inspect "" >/dev/null 2>&1 || docker volume create ""
    echo "volume ready: "
done
