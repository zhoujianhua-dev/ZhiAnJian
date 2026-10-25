# 智安鉴前端（React 18 + TS + Vite + Tailwind）开发约定

> 本文件是页面迁移的唯一规范来源。所有页面必须复用下列组件与模式，**不要**引入新的 npm 依赖，
> **不要**修改 `src/components/ui/*`、`src/layout/*`、`src/lib/*`、`src/App.tsx`（如确需改动，先在交付说明里写清原因）。

## 目录

```
frontend/
  src/
    main.tsx / App.tsx            # 入口与路由（已配置好，无需改动）
    index.css                     # 设计令牌与全局样式
    lib/                          # api / format / theme / use-query / sanitize / cn
    components/ui/                # 通用组件（见下）
    layout/                       # 侧栏、顶栏、页面骨架
    pages/                        # 一个页面一个文件
    pages/tools/                  # 工具箱页面
```

## 设计风格：现代扁平

- 纯色块 + 1px 描边，**禁止**渐变（`bg-gradient-*`）、毛玻璃（`backdrop-blur`）、大阴影。
- 卡片：`rounded-lg border border-line bg-surface shadow-card`（用 `<Card>`）。
- 圆角：控件 `rounded-md`（6px），卡片 `rounded-lg`（8px），徽章 `rounded`（4px）。
- 间距：卡片内边距 `p-4`，栅格间距 `gap-3` / `gap-4`；页面根节点用 `flex flex-col gap-4`。
- 字号：正文 13px（`text-[13px]`），次要信息 `text-xs text-slate-500`，标题 `text-[15px] font-semibold`。
- 主色只用 `text-primary` / `bg-primary` / `bg-primary-soft` / `border-primary`；**不要**用 `bg-primary/10`（CSS 变量不支持透明度修饰符）。
- 危险操作用红色（`text-red-600` / `variant="danger"`），成功用 `emerald`，警告用 `amber`。
- 表格里的行内操作统一用 `<LinkButton>`；顶部主操作放工具栏右侧。
- 不写内联 `<style>`；样式一律用 Tailwind 类。

## 数据请求

```ts
import { api } from '@/lib/api'
import { useQuery } from '@/lib/use-query'

const load = useCallback(async () => {
  const res = await api.get<Item[]>('/api/items', { page, limit: 10, keyword })
  return { rows: res.data || [], total: res.count || 0 }
}, [page, keyword])

const { data, loading, error, reload } = useQuery(load, [load])
```

- `api.get<T>(path, query?)`、`api.post<T>(path, json?)`、`api.upload<T>(path, formData)`。
- 接口业务失败（`code!==0`）或 HTTP 非 2xx 会抛 `ApiError`（`message` 即可展示的中文）。
- 登录失效由 `api` 自动跳转登录页，页面无需处理。
- 写操作统一 `try/catch`：成功 `toast.success(res.msg || '已保存')`，失败 `toast.error(e instanceof Error ? e.message : '操作失败')`。
- 提交按钮用 `loading={saving}`，避免重复提交。
- 导出/下载：后端返回 `{ url }` 时用 `downloadFile(url)`；直接下载类接口用 `downloadFile('/api/...')`。
- 文件选择用 `pickFile(accept, multiple)`。

## 交互反馈

```ts
const toast = useToast()      // success / error / info / warning
const confirm = useConfirm()  // await confirm({ message, confirmText }) => boolean
```

- **所有删除/清空/覆盖类操作必须先 `await confirm(...)`**。
- 列表为空用 `<EmptyState title description action />`，首次加载用 `<LoadingBlock />`，请求失败用 `<ErrorBlock message onRetry />`。
- 表单校验错误就地展示（`Field` 的 `error` 或 toast），不要用 `alert`。

## 组件清单（全部已实现，直接 import）

```ts
import { Button, LinkButton } from '@/components/ui/button'
// variant: primary | secondary | ghost | danger | success | warning | link；size: sm | md；icon / loading / block

import { Card, CardHeader, CardBody, CardFooter, PageIntro } from '@/components/ui/card'
// CardHeader({ title, description?, actions? })

import { Field, Input, Textarea, Select, Checkbox, Switch, inputCls, textareaCls } from '@/components/ui/field'
// Field({ label, required, hint, error, className }) 包住控件

import { Modal } from '@/components/ui/modal'          // open, onClose, title, footer, size: sm|md|lg|xl
import { DataTable, KV, type Column } from '@/components/ui/table'
import { Pagination, EmptyState, LoadingBlock, ErrorBlock } from '@/components/ui/states'
import { Tabs } from '@/components/ui/tabs'            // items: {key,label,icon?,badge?}, value, onChange, variant: line|segment
import { Badge, SeverityBadge, LifecycleBadge, TagChip } from '@/components/ui/badge'
import { ImageZone } from '@/components/ui/image-zone' // value: string[], onChange
import { RichTextEditor, RichTextView } from '@/components/ui/rich-text'
import { SuggestInput } from '@/components/ui/suggest-input'
```

`Column<T>`：`{ key, title, render: (row, index) => ReactNode, width?, align?, className? }`

`DataTable` 关键属性：`columns / rows / rowKey / loading / empty / selectable / selectedKeys / onSelectedChange / onRowClick`。

## 格式化工具（`@/lib/format`）

`SEVERITY_LABEL`、`SEVERITY_ORDER`、`severityLabel()`、`severityOf()`、
`LIFECYCLE_LABEL`、`LIFECYCLE_ORDER`、`lifecycleLabel()`、`lifecycleOf()`、
`fmtTime()`、`fmtDate()`、`fmtTimeUtc8()`（扫描引擎 UTC 时间转北京时间）、`extractHost()`、`splitLines()`、`truncate()`。

## TypeScript

- `strict` 已开启，禁止 `any`（用 `unknown` + 类型收窄，或定义本地接口）。
- 每个页面在文件内定义自己用到的接口，接口字段与后端返回保持一致（后端为 snake_case）。
- 不使用 `enum`，用联合类型 + `as const` 常量表。
- 不使用 `React.FC`，直接 `export function XxxPage() {}`。

## 迁移要求

- 迁移时的旧 Jinja 模板已从仓库删除（需要对照历史版本时看 git 记录），页面以现有实现为准。
- 旧页面里通过 `ZhiShield.*` 提供的工具能力，在新前端里都有对应组件（富文本、多图上传、分页、徽章、确认框、Toast、主机名提取）。
- 表格列顺序、按钮文案、空状态提示尽量与旧页面一致，便于用户平滑过渡。
- 页面根节点不要写死高度；内容区宽度由布局统一控制。
