import { useMemo, useState } from 'react'
import { Copy, Play } from 'lucide-react'
import { Card, CardBody, CardHeader, PageIntro } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/field'
import { DataTable, type Column } from '@/components/ui/table'
import { EmptyState } from '@/components/ui/states'
import { useToast } from '@/components/ui/toast'
import { api } from '@/lib/api'
import { TOOL_ICONS } from '@/layout/nav'

const Icon = TOOL_ICONS['/tools/urls']

/** 与 core/tools.process_url_text 返回结构一致 */
interface UrlRow {
  input: string
  result: string
  targets: string[]
  multi: boolean
}

const PLACEHOLDER = [
  'https://www.example.com/path',
  'http://192.168.1.1:8080/admin',
  'sub.example.com:443',
].join('\n')

const UNKNOWN_PREFIX = '无法识别'

export function ToolUrls() {
  const toast = useToast()

  const [text, setText] = useState('')
  const [rows, setRows] = useState<UrlRow[] | null>(null)
  const [loading, setLoading] = useState(false)

  /** 提取出的主域名 / IP（去重保序），用于一键复制 */
  const extracted = useMemo(() => {
    const seen = new Set<string>()
    const list = rows || []
    list.forEach((row) => {
      if (row.result.startsWith(UNKNOWN_PREFIX)) return
      row.result.split('、').forEach((v) => {
        const t = v.trim()
        if (t) seen.add(t)
      })
    })
    return Array.from(seen)
  }, [rows])

  async function extract() {
    setLoading(true)
    try {
      const res = await api.post<UrlRow[]>('/api/tools/urls', { text })
      setRows(res.data || [])
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '提取失败')
    } finally {
      setLoading(false)
    }
  }

  async function copyResult() {
    if (!extracted.length) {
      toast.info('暂无可复制的识别结果')
      return
    }
    try {
      await navigator.clipboard.writeText(extracted.join('\n'))
      toast.success('已复制')
    } catch {
      toast.error('复制失败')
    }
  }

  const columns: Column<UrlRow>[] = [
    {
      key: 'input',
      title: '原始输入',
      render: (row) => <span className="block break-all text-slate-500">{row.input}</span>,
    },
    {
      key: 'result',
      title: '主域名 / IP',
      render: (row) => {
        const parts = row.multi && row.result.includes('、') ? row.result.split('、') : []
        if (parts.length) {
          return (
            <div>
              <div className="flex flex-wrap gap-1.5">
                {parts.map((v) => (
                  <Badge key={v} tone="blue">
                    {v}
                  </Badge>
                ))}
              </div>
              <p className="mt-1 text-[11.5px] text-slate-400">本行自动识别出 {parts.length} 个资产</p>
            </div>
          )
        }
        if (row.result.startsWith(UNKNOWN_PREFIX)) {
          return <span className="text-red-600">{row.result}</span>
        }
        return <span className="font-semibold text-primary">{row.result}</span>
      },
    },
  ]

  return (
    <div className="flex flex-col gap-4">
      <PageIntro
        icon={<Icon size={18} />}
        title="提取域名 / IP"
        description="从 URL、域名或 IP:端口 中提取主域名与 IP，夹带自然语言的行会自动识别其中的多个资产。"
      />

      <Card>
        <CardHeader
          title="输入文本"
          description="每行一个 URL / 域名 / IP:端口，自动提取主域名或 IP。"
        />
        <CardBody className="flex flex-col gap-3">
          <Textarea
            rows={10}
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={PLACEHOLDER}
          />
          <div>
            <Button variant="primary" icon={<Play size={14} />} loading={loading} onClick={extract}>
              提取
            </Button>
          </div>
        </CardBody>
      </Card>

      {rows ? (
        <Card>
          <CardHeader
            title="提取结果"
            description={`共 ${rows.length} 行，识别 ${extracted.length} 个资产`}
            actions={
              <Button size="sm" variant="secondary" icon={<Copy size={13} />} onClick={copyResult}>
                复制结果
              </Button>
            }
          />
          <DataTable
            columns={columns}
            rows={rows}
            rowKey={(row, i) => `${i}-${row.input}`}
            loading={loading}
            empty={
              <EmptyState
                title="无有效输入"
                description="请粘贴 URL / 域名 / IP:端口，每行一个后重新提取"
              />
            }
          />
        </Card>
      ) : null}
    </div>
  )
}
