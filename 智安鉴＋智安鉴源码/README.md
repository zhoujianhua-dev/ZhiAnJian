# 智安鉴 · 智能安全检测与漏洞报告系统

> 基于大模型与 RAG 的智能安全检测与漏洞报告系统

---

## 一、快速开始

### 1. 环境要求
- Windows 10/11（其他系统亦可）
- Python 3.10（已内置 pip）

### 2. 启动（推荐：双击启动脚本，自动装依赖）
直接双击目录下的 **`启动智安鉴.bat`** 即可：脚本自动识别 Python，**首次运行自动安装依赖**，随后启动服务并打开浏览器，全程无需命令行。

命令行方式（可选）：
```bash
py -3.10 -m pip install -r requirements.txt   # 仅首次需要
py -3.10 app.py
```
启动后浏览器访问 **http://127.0.0.1:8080**。如需更换端口，先设置环境变量（如 `set ZS_PORT=8090`）再启动即可。

### 4. 可选：导入演示数据
进入「系统设置 → 数据管理 → 导入演示数据」，一键写入测试单位/域名/漏洞，便于快速体验。

---

## 二、功能总览

| 模块 | 功能 |
|---|---|
| 仪表盘 | 资产数据总览、漏洞等级环形图、**近 6 个月报告趋势柱状图、报告数量 TOP 单位**、最近报告、快捷入口 |
| 单位管理 | 单位台账、批量导入（文本/Excel）、ICP 数据包导入、标签化管理、批量查询 |
| 域名资产 | ICP 备案域名管理、JSON 数据导入（兼容 3 种格式）、模糊查询、软删除 |
| 漏洞库 | 漏洞名称/等级/描述/危害/整改建议知识维护，报告自动引用，作为本地 RAG 知识源；**英文漏洞名（Nuclei 模板）自动翻译为中文，英文原名保留可追溯，支持一键批量翻译** |
| 报告管理 | 报告增删改查、多条件检索、勾选批量导出、导出历史；检测过程图与归属证明图各自多图留证；填漏洞地址自动识别域名，保存即自动联动登记单位/域名；**Word/PDF 多模板（普通/公文/汇总/自定义）** |
| **AI 智能生成** | 扫描器原始数据 → 结构化报告字段 → Word/PDF 一键导出；**本地知识库 RAG 检索增强**、AI 润色/摘要/资产分类 |
| **AI 漏洞扫描** | **内置扫描引擎一键全量扫描：可预填所属单位/系统，实时看子 Agent 进度、过程日志与攻击链；扫描结果可勾选后直接「加入报告管理」（自动带入单位/系统、登记资产并写入漏洞库）** |
| **扫描器导入** | **上传 Nuclei(JSONL/JSON)、通用 JSON、纯文本扫描结果，自动识别漏洞名称/地址/等级并统计** |
| **质量体检** | **九维加权规则引擎 0–100 分自动评分、缺项定位、同单位同漏洞重复检测，并给出 AI 专家点评** |
| **AI 安全助手** | **SSE 流式多轮对话：漏洞原理分析、检测步骤设计、整改建议、多语言修复代码生成、报告 AI 评分** |
| **CVSS 评分器** | **严格遵循 FIRST.org CVSS v3.1，8 项指标实时算分定级、向量字符串解析、一键回填报告** |
| 工具集 | 随机密码、文本去重、域名/IP 提取、A/B 对比、资产分类 |
| 模板与个性化 | **上传任意成品漏洞报告 docx 一键逆向成同版式可复用模板**；自定义背景图、主题色、系统标题、AI 接口配置、数据管理 |

---

## ★ 智能能力亮点

- **扫描器结果一键导入**：支持 Nuclei（JSONL/JSON）、通用安全扫描 JSON 与纯文本，自动抽取漏洞名称、地址与等级，高危/中危/低危自动统计，导入后可直接进入 AI 整理与报告生成。
- **本地知识库 RAG 检索增强**：AI 生成前先从本地漏洞知识库做零外部向量库的中文加权相似检索，把相关标准描述、危害与修复方案注入提示词，让生成内容更贴合本机构规范、可追溯。
- **报告质量智能体检**：从单位名称、漏洞名称、等级、地址、描述、危害、检测过程、整改建议、归属证明九个维度加权扣分，输出 0–100 分与优秀/良好/合格/待完善等级，逐条列出问题并给出 AI 专家点评。
- **AI 安全专家 Copilot**：基于 SSE 的流式多轮对话，支持漏洞原理分析、检测步骤设计、整改建议、多语言安全修复代码生成，以及对单份报告的规则+AI 双维评分。
- **CVSS v3.1 标准评分**：严格实现 FIRST.org CVSS v3.1 基础评分公式（含 Scope 改变时的影响分修正），8 项指标实时算分、风险等级映射与向量字符串双向解析。
- **PDF 多模板导出**：除三套 Word 模板外，reportlab 渲染 PDF（自动调用 Windows 中文字体），富文本与证据图片等比排版，普通/公文/汇总三种版式。

> 全部 AI 能力在无 Key 时以**模拟模式**完整可演示（密钥填 `sk-test-mock` 或勾选模拟模式）；
> 配置真实兼容 OpenAI 协议的接口后自动切换为真实大模型，两条链路共用同一接口，无“假按钮”。

---

## 三、AI 配置说明（可选，不影响其他功能）

在「系统设置 → AI 接口配置」中填写：

| 接入方 | Base URL | 模型示例 |
|---|---|---|
| 阶跃星辰（标准） | `https://api.stepfun.com/v1` | `step-3.5-flash` / `step-3.7-flash` |
| 阶跃星辰（套餐/step_plan） | `https://api.stepfun.com/step_plan/v1` | `step-3.5-flash` / `step-3.7-flash` |
| DeepSeek | `https://api.deepseek.com/v1` | `deepseek-chat` |
| 通义千问 | `https://dashscope.aliyuncs.com/compatible-mode/v1` | `qwen-turbo` |
| OpenAI | `https://api.openai.com/v1` | `gpt-4o-mini` |
| 本地 Ollama | `http://localhost:11434/v1` | `qwen2.5:7b` |

- Base URL 请按所用账户的实际端点**原样填写**（套餐用户即为含 `/step_plan/` 的地址，系统不会改写）；模型名可在对应平台账户的“可用模型列表”中查询。
- 已对思考型模型做兼容：当模型偶发“只生成思考、未输出结论”时会自动重试；结构化任务（分析/修复/评分）已预留充足输出长度，避免 JSON 被截断。
- API Key 仅保存在本机 `config.json`，不写入数据库、不出现在报告与日志中；但如需把源码**公开或上传比赛平台**，请先在「系统设置 → AI 接口配置」清空 API Key，避免凭据外泄。
- 无 Key 时可在「AI 智能生成」页勾选 **模拟模式**，使用内置演示数据联调全流程。

---

## 四、报告模板自定义

系统首次启动即**内置并默认选中「标准模板（与原工具一致）」**（随源码分发于 `assets/builtin_templates/标准漏洞报告模板.docx`），导出默认就按熟悉的占位符版式自动填充，无需配置。

制作属于自己的模板：
1. 在「报告管理 → 模板管理」点击「⬇ 下载系统标准模板（含占位符）」；
2. 用 Word/WPS 按本单位格式调整抬头、字体、章节、表格，把需自动填写处保留或写上 `{{占位符}}`，另存为 `.docx`；
3. 上传该 `.docx`——系统**自动识别并回显其中可填充的字段**，可设为默认；
4. 导出时选择「标准模板」并在下拉中挑选你的模板，系统自动按占位符填充，**你的版式原样保留**（富文本还原真实换行、证据图片等比插入、多记录自动合并）。

支持的 13 个占位符：
```
{{单位名称}} {{漏洞名称}} {{系统名称}} {{域名}} {{漏洞地址}} {{漏洞描述}}
{{检测过程}} {{漏洞等级}} {{漏洞危害}} {{整改建议}} {{归属证明}}
{{报告日期}} {{单位落款}}
```
> 内置模板为幂等引导：删除后重启会自动恢复；用户上传的模板不受影响。

---

## 五、目录结构

```
智安鉴智能安全检测与漏洞报告系统/
├── app.py                 # 主程序入口
├── config.py              # 系统配置
├── database.py            # 数据访问层（MySQL / PyMySQL）
├── config.json            # 用户配置（背景/AI Key 等，本地）
├── core/                  # 核心引擎
│   ├── exporter.py        # Word 报告导出引擎（内置+自定义模板）
│   ├── pdf_export.py      # PDF 导出引擎（普通/公文/汇总三套，内置中文字体）
│   ├── ai_engine.py       # AI 引擎（多模型 / RAG / 流式 / 修复代码 / AI 评分）
│   ├── scanners.py        # 扫描器结果解析（Nuclei/通用JSON/纯文本）
│   ├── cvss.py            # CVSS v3.1 标准评分（FIRST.org）
│   ├── qa.py              # 报告质量九维体检规则引擎
│   ├── tools.py           # 工具箱算法
│   ├── vuln_translate.py  # 漏洞名称中文化（安全术语词典）
│   └── helpers.py         # 通用辅助
├── routes/                # 业务路由（单位/域名/漏洞/报告/AI/扫描器/工具/设置）
├── scripts/               # 运维脚本（SQLite → MySQL 数据迁移）
├── frontend/              # 前端源码（React 18 + TypeScript + Vite + Tailwind）
│   ├── src/pages/         # 页面（仪表盘/单位/域名/漏洞/报告/AI/扫描/工具/设置）
│   ├── src/components/ui/ # 通用组件（表格/弹窗/表单/富文本/多图上传…）
│   ├── src/lib/           # API 客户端、格式化、主题、Hooks
│   └── CONVENTIONS.md     # 前端开发约定
├── static/app/            # 前端构建产物（npm run build 生成，随仓库提交）
├── data/                  # 运行时数据（数据库、导出报告、上传图片、背景图、模板）
├── docs/                  # 作品报告、原创性声明、展示PPT、演示视频、测试/部署文档、构建脚本
├── test_e2e.py            # 第一轮端到端测试（20 项）
├── test_phase2.py         # 第二轮增强功能回归测试（24 项）
├── 启动智安鉴.bat          # Windows 一键启动
└── requirements.txt       # 依赖清单
```

---

## 六、前端开发（React）

页面已从 Jinja 服务端渲染迁移为 **React 18 + TypeScript + Vite + Tailwind** 单页应用，
视觉统一为现代扁平风格（纯色块 + 1px 描边，无渐变/毛玻璃）。

- 构建产物在 `static/app/`，**已随仓库提交**：无需安装 Node 即可运行前端；
- 业务数据在 MySQL 8，本地运行前需先启动数据库（推荐 `docker compose up -d mysql`），
  并配置环境变量 `ZS_DB_HOST / ZS_DB_PORT / ZS_DB_USER / ZS_DB_PASSWORD / ZS_DB_NAME`；
- 改前端源码后需要重新构建：

```bash
cd frontend
npm install
npm run build        # 产物写入 ../static/app
```

- 开发调试（热更新，接口自动代理到 8080）：

```bash
python app.py                    # 终端 A：后端
cd frontend && npm run dev       # 终端 B：前端 http://localhost:5173
```

- 页面路由、鉴权、请求封装、组件约定见 `frontend/CONVENTIONS.md`；
- 容器部署：`Dockerfile` 已改为多阶段构建，Node 阶段编译前端后再拷入 Python 镜像；

---

## 七、数据与安全

- 业务数据存储于 MySQL 8（compose 卷 `zhianjian_mysql_data`），**数据不出本机**；
  ⚠️ 升级/重装请用 `docker compose down`（**不要带 `-v`**），否则会连同数据库卷一起删除；
- 导出报告、上传图片、背景图、报告模板仍存放在 `data/` 目录；
- AI 密钥仅存于本地 `config.json`；
- 写操作启用 CSRF Token 校验，前端渲染富文本前统一做 HTML 清洗（去脚本/内联事件/javascript: 协议）防 XSS；
- 文件上传白名单校验，下载路径防目录穿越；
- 报告导出文件保存在 `data/exports/`，可随时在「报告管理 → 导出历史」重新下载。

---

## 八、常见问题

**Q1：启动提示缺少依赖？**
执行 `py -3.10 -m pip install -r requirements.txt` 后重新启动。

**Q2：8080 端口被占用？**
修改 `app.py` 末尾的 `port=8080` 为其他端口后重启。

**Q3：启动报「无法连接 MySQL」？**
先启动数据库：`docker compose up -d mysql`；本地直连时确认 `ZS_DB_*` 环境变量与 MySQL 账号密码一致。
从旧版 SQLite 升级可执行 `python3 scripts/migrate_sqlite_to_mysql.py` 迁移历史数据。

**Q3：AI 生成提示接口失败？**
检查「系统设置 → AI 接口配置」中 Base URL 与模型是否匹配、Key 是否有效，或切换为模拟模式。

**Q4：如何清空数据重新开始？**
「系统设置 → 数据管理 → 清空全部业务数据」。

**Q5：自定义模板占位符没被填充？**
确认占位符与上表完全一致（含花括号），且模板为 `.docx` 格式。

---

## 九、自动化测试

系统附带两套真实 HTTP 回归脚本（需先启动服务）：

```bash
py -3.10 test_e2e.py      # 第一轮核心业务全流程 20 项
py -3.10 test_phase2.py   # 第二轮增强功能 24 项（CVSS/扫描器/体检/PDF/RAG/AI）
```

当前结果：**44 项全部通过**，并经真实 Chrome/Edge 内核浏览器端到端逐页验证。详见 `docs/` 下《系统测试报告》。

## 十、配套交付物（仓库根目录）

- 作品报告（docx + PDF，七章结构）
- 展示 PPT（16:9，含 PDF 版）
- 功能演示视频（MP4，约 3 分 46 秒，中文讲解 + 字幕）
- 全套系统运行截图（png + zip 打包）

---

## 十一、扫描引擎一体化部署（scan-engine）

仓库结构：

- 根目录：智安鉴业务系统（Flask，端口 8080，数据存 MySQL 8）
- `scan-engine/`：内置漏洞扫描引擎（原 Shelling），含 `backend/`（FastAPI 与 Celery 任务）、
  `docker/`（Kali 工具容器与三个 Dockerfile）、`frontend/`（Vite，端口 3000）

一条命令起全部服务：

```bash
cp config.example.json config.json                                   # 填 AI Key 与 shelling.password
cp scan-engine/backend/.env.example scan-engine/backend/.env         # 填 SECRET_KEY / JWT_SECRET_KEY
docker compose up -d --build                                         # 8080 智安鉴 / 3000 引擎前端 / 8000 引擎 API / 8888 Kali
```

数据与端口：

| 服务 | 端口 | 存储 |
|---|---|---|
| 智安鉴 | 8080 | MySQL 卷 `zhianjian_mysql_data` + ${DATA} 目录（导出/图片/模板）+ ${CONFIG} 文件 |
| 智安鉴 MySQL | 3306 | 卷 `zhianjian_mysql_data`（utf8mb4） |
| 引擎 backend / celery | 8000 | PostgreSQL 卷 docker_postgres_data、Mongo docker_mongodb_data、Redis docker_redis_data |
| Kali 扫描容器 | 8888 | docker_kali_tools / docker_kali_output / docker_kali_logs / docker_kali_tmp、docker_tools_data |
| 引擎前端 | 3000 | 卷 64ddc45c45d7…（node_modules） |

说明：

1. compose 中卷名显式指向历史卷（docker_ 前缀），合并部署不会新建空卷，已有的扫描任务与账号直接沿用。
2. 智安鉴默认按容器网内地址访问引擎后端（服务名 backend，端口 8000），默认值写在 config.py 的 DEFAULTS 里；可在 config.json 的 shelling 段覆盖，引擎若部署在别处只改 base_url 即可，界面无需任何配置。
   引擎若部署在别处，只改 `base_url` 即可，界面无需任何配置。
3. 引擎侧 `.dockerignore` 已排除 `.env`，密钥只在运行期通过 bind mount 进入容器，不会落进镜像层。
4. 智安鉴镜像的 `.dockerignore` 已排除 `.git/`、`data/`、`config.json`、`scan-engine/`，
   避免源码历史、业务数据库与密钥被烘进镜像。
5. 引擎自带的前端是 Vite 开发服务器；若要对外，建议在前面加一层 Nginx/Caddy 并启用 TLS。
