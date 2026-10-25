# 扫描临时文件管理

## 概述

所有扫描工具的输出文件现在统一存储在临时目录中，不再污染项目源代码目录。

## 配置

临时目录位置在 `backend/app/core/config.py` 中配置：

```python
scan_temp_dir: str = "/tmp/shelling_scans"  # 默认临时目录
```

可通过环境变量覆盖：

```bash
export SCAN_TEMP_DIR=/var/tmp/scans
```

## 目录结构

```
/tmp/shelling_scans/
├── nmap/          # Nmap 扫描结果
├── nuclei/        # Nuclei 扫描结果
└── web/           # Web 扫描结果
```

## 使用扫描器的临时目录

在扫描器中使用基类提供的方法：

```python
from scanners.base import BaseScanner

class MyScanner(BaseScanner):
    async def scan(self, target: str, config: dict):
        # 获取扫描器专用临时目录
        temp_dir = self.get_temp_dir()
        
        # 创建临时文件
        temp_file = self.get_temp_file(prefix="scan_", suffix=".json")
        
        # 使用临时文件...
```

## 清理旧文件

### 手动清理

```bash
# 清理 24 小时前的文件（默认）
python backend/scripts/cleanup_temp_scans.py

# 清理 12 小时前的文件
python backend/scripts/cleanup_temp_scans.py --max-age 12

# 清理 1 小时前的文件
python backend/scripts/cleanup_temp_scans.py --max-age 1
```

### 自动清理（Cron）

添加到 crontab 每天自动清理：

```bash
# 每天凌晨 3 点清理超过 24 小时的临时文件
0 3 * * * cd /root/shelling && python backend/scripts/cleanup_temp_scans.py
```

### Docker 环境

在 Docker Compose 中可以挂载 tmpfs：

```yaml
services:
  api:
    volumes:
      - type: tmpfs
        target: /tmp/shelling_scans
        tmpfs:
          size: 1G  # 限制最大 1GB
```

## 最佳实践

1. **扫描器应该**：
   - 使用 `get_temp_dir()` 或 `get_temp_file()` 获取临时路径
   - 在内存中处理数据时，不需要创建临时文件
   - 扫描完成后，原始数据应存入 MongoDB，不依赖临时文件

2. **不要**：
   - 在项目源代码目录中写入扫描结果
   - 假设临时文件会永久保存
   - 在临时文件中存储敏感信息（使用后应立即删除）

3. **清理策略**：
   - 开发环境：可以设置较短的保留时间（如 1-2 小时）
   - 生产环境：建议 24 小时，配合定时清理任务

## 监控磁盘使用

```bash
# 查看临时目录大小
du -sh /tmp/shelling_scans

# 查看各扫描器目录大小
du -h --max-depth=1 /tmp/shelling_scans
```

## 故障排查

### 临时目录权限问题

```bash
# 确保应用有写权限
sudo chown -R $(whoami) /tmp/shelling_scans
sudo chmod -R 755 /tmp/shelling_scans
```

### 磁盘空间不足

```bash
# 立即清理所有临时文件
python backend/scripts/cleanup_temp_scans.py --max-age 0
```
