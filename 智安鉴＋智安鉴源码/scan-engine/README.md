# Hack Scan AI

Hack Scan AI 是一个集成大语言模型（LLM）的自动化漏洞扫描平台，提供扫描、分析、攻击路径与报告能力，面向安全测试与运营团队使用。

## 功能特性

- 自动化漏洞扫描：Nmap / Nuclei
- AI 分析与风险评分：输出可读的管理层摘要与关键建议
- 攻击路径分析：扫描完成后自动生成攻击链与风险评估
- 报告导出：Markdown / HTML / CSV / JSON
- 知识库：上传并管理脚本、模板、字典、配置、扫描器、AI Skill
- AI Agent 扩展测试：自动执行补充验证与复测建议

## 架构图

```mermaid
flowchart LR
  UI[Frontend\nReact] --> API[Backend\nFastAPI]
  API --> Worker[Celery Worker]
  API --> PG[(PostgreSQL\n结构化数据)]
  API --> Mongo[(MongoDB\n原始数据)]
  Worker --> Scanner[Nmap / Nuclei\nScanners]
  Worker --> LLM[LLM API\n分析/总结]
  Worker --> PG
  Worker --> Mongo
```

## 流程图

```mermaid
flowchart TD
  A[用户创建扫描任务] --> B[后台初始化扫描]
  B --> C[运行扫描器\nNmap / Nuclei]
  C --> D[保存发现与日志]
  D --> E[AI 漏洞分析与风险评分]
  E --> F[生成攻击路径分析]
  F --> G[生成报告摘要与导出]
  G --> H[前端展示报告/修复建议]
```

## 快速开始（Docker Compose）

```bash
docker compose up --build -d
```

- 前端：<http://localhost:3000>
- 后端 API：<http://localhost:8000>
- API 文档：<http://localhost:8000/docs>

## 本地开发

1. 启动依赖服务
```bash
docker compose up -d postgres mongodb redis
```

2. 启动后端
```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

uvicorn app.main:app --reload
```

3. 启动 Celery Worker（新终端）
```bash
cd backend
celery -A tasks.celery_app worker --loglevel=info
```

4. 启动前端
```bash
cd frontend
npm install
npm run dev
```

## 配置说明（常用）

| 变量 | 说明 | 默认值 |
|------|------|--------|
| POSTGRES_URL | PostgreSQL 连接串 | postgresql+asyncpg://postgres:postgres@localhost:5432/vulnscanner |
| MONGODB_URL | MongoDB 连接串 | mongodb://localhost:27017 |
| REDIS_URL | Redis 连接串 | redis://localhost:6379/0 |
| KALI_SCANNER_URL | Kali 扫描服务 | http://kali_scanner:8888 |
| TOOLS_DIR | 知识库存储路径 | /app/data/tools |

## API 示例

```bash
# 创建扫描任务
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "scan_type": "quick"}'

# 获取扫描结果
curl http://localhost:8000/api/v1/scans/{scan_id}

# 获取漏洞列表
curl http://localhost:8000/api/v1/scans/{scan_id}/vulnerabilities
```

## 扫描器

- **Nmap**：端口扫描、服务识别、漏洞脚本
- **Nuclei**：模板化漏洞检测
- **自定义扫描器**：可通过知识库上传并管理

## 安全提示

1. 仅对授权目标进行扫描，避免非法测试
2. 控制扫描频率，避免对目标造成压力
3. 敏感数据请脱敏后再提交给公共 LLM
