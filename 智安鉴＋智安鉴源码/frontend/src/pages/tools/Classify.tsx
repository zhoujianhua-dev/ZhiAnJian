import { useMemo, useState } from 'react'
import { Play } from 'lucide-react'
import { Card, CardBody, CardHeader, PageIntro } from '@/components/ui/card'
import { Badge, type BadgeTone } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/field'
import { DataTable, type Column } from '@/components/ui/table'
import { EmptyState } from '@/components/ui/states'
import { useToast } from '@/components/ui/toast'
import { api } from '@/lib/api'
import { TOOL_ICONS } from '@/layout/nav'

const Icon = TOOL_ICONS['/tools/classify']

/** 与 core/tools.classify_assets 返回结构一致；source 仅在一行夹带多个资产时出现 */
interface ClassifyItem {
  input: string
  type: string
  value: string
  source?: string
}

interface ClassifyResult {
  items: ClassifyItem[]
  stats: Record<string, number>
  total: number
}

const PLACEHOLDER = [
  'https://www.example.com',
  '192.168.1.10:8080',
  'user@example.com',
  '13800138000',
  'app.example.com',
].join('\n')

const TYPE_TONE: Record<string, BadgeTone> = {
  URL: 'blue',
  域名: 'green',
  IP: 'sky',
  'IP:端口': 'sky',
  IPv6: 'sky',
  邮箱: 'amber',
  手机号: 'amber',
  文件路径: 'slate',
  其他: 'slate',
  空: 'slate',
}

const TYPE_ORDER = ['URL', '域名', 'IP', 'IP:端口', 'IPv6', '邮箱', '手机号', '文件路径', '其他']

function toneOf(type: string): BadgeTone {
  return TYPE_TONE[type] || 'slate'
}

interface TypeGroup {
  type: string
  count: number
  items: ClassifyItem[]
}

export function ToolClassify() {
  const toast = useToast()

  const [text, setText] = useState('')
  const [result, setResult] = useState<ClassifyResult | null>(null)
  const [loading, setLoading] = useState(false)

  const groups = useMemo<TypeGroup[]>(() => {
    if (!result) return []
    const types = Object.keys(result.stats)
    const ordered = [...TYPE_ORDER.filter((t) => types.includes(t)), ...types.filter((t) => !TYPE_ORDER.includes(t))]
    return ordered
      .filter((t) => (result.stats[t] || 0) > 0)
      .map((t) => ({
        type: t,
        count: result.stats[t] || 0,
        items: result.items.filter((it) => it.type === t),
      }))
  }, [result])

  async function classify() {
    setLoading(true)
    try {
      const res = await api.post<ClassifyResult>('/api/tools/classify', { text })
      setResult(res.data || null)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '分类失败')
    } finally {
      setLoading(false)
    }
  }

  const columns: Column<ClassifyItem>[] = [
    {
      key: 'input',
      title: '原始输入',
      render: (item) => (
        <div className="flex flex-col">
          <span className="break-all text-slate-500">{item.input}</span>
          {item.source && item.source !== item.input ? (
            <span className="break-all text-[11px] text-slate-400">来自：{item.source}</span>
          ) : null}
        </div>
      ),
    },
    {
      key: 'type',
      title: '类型',
      width: 110,
      render: (item) => <Badge tone={toneOf(item.type)}>{item.type}</Badge>,
    },
    {
      key: 'value',
      title: '提取值',
      render: (item) => <span className="break-all font-semibold text-primary">{item.value}</span>,
    },
  ]

  return (
    <div className="flex flex-col gap-4">
      <PageIntro
        icon={<Icon size={18} />}
        title="资产分类"
        description="识别 URL / 域名 / IP / IP:端口 / IPv6 / 邮箱 / 手机号等资产类型，并按类型分组统计。"
      />

      <Card>
        <CardHeader
          title="输入资产信息"
          description="每行一条，支持 URL / 域名 / IP / IP:端口 / 邮箱 / 手机号等；夹带自然语言的行会自动抽取其中的资产。"
        />
        <CardBody className="flex flex-col gap-3">
          <Textarea
            rows={10}
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={PLACEHOLDER}
          />
          <div>
            <Button variant="primary" icon={<Play size={14} />} loading={loading} onClick={classify}>
              开始分类
            </Button>
          </div>
        </CardBody>
      </Card>

      {result ? (
        <Card>
          <CardHeader title="分类结果" description={`共识别 ${result.total} 条资产，按类型分组展示。`} />
          <CardBody className="flex flex-col gap-4">
            <div className="flex flex-wrap items-center gap-2">
              {groups.length ? (
                groups.map((g) => (
                  <Badge key={g.type} tone={toneOf(g.type)}>
                    {g.type} × {g.count}
                  </Badge>
                ))
              ) : (
                <span className="text-[13px] text-slate-400">无数据</span>
              )}
            </div>

            {groups.length ? (
              <div className="flex flex-col gap-4">
                {groups.map((g) => (
                  <div key={g.type} className="overflow-hidden rounded-md border border-line">
                    <div className="flex items-center gap-2 border-b border-line bg-slate-50 px-3 py-2">
                      <Badge tone={toneOf(g.type)}>{g.type}</Badge>
                      <span className="tnum text-xs text-slate-500">共 {g.count} 条</span>
                    </div>
                    <DataTable columns={columns} rows={g.items} rowKey={(item, i) => `${g.type}-${i}-${item.input}`} />
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState title="暂无数据" description="请粘贴资产信息后重新分类" />
            )}
          </CardBody>
        </Card>
      ) : null}
    </div>
  )
}
