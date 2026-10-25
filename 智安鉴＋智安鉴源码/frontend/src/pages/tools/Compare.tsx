import { useMemo, useState } from 'react'
import { Copy, Play, Upload } from 'lucide-react'
import { Card, CardBody, CardHeader, PageIntro } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/field'
import { DataTable, type Column } from '@/components/ui/table'
import { EmptyState } from '@/components/ui/states'
import { useToast } from '@/components/ui/toast'
import { api, pickFile } from '@/lib/api'
import { TOOL_ICONS } from '@/layout/nav'

const Icon = TOOL_ICONS['/tools/compare']

/** 与 core/tools.align_columns 返回结构一致 */
interface CompareResult {
  aligned_a: string
  aligned_b: string
  only_a: string
  only_b: string
  common_count: number
  a_count: number
  b_count: number
}

interface AlignedRow {
  a: string
  b: string
}

function toLines(text: string): string[] {
  return text ? text.split('\n').filter(Boolean) : []
}

function DiffPanel({
  title,
  lines,
  prefix,
  tone,
  onCopy,
}: {
  title: string
  lines: string[]
  prefix: string
  tone: 'red' | 'green'
  onCopy: () => void
}) {
  return (
    <div className="rounded-md border border-line">
      <div className="flex items-center justify-between gap-2 border-b border-line bg-slate-50 px-3 py-2">
        <span className="text-[13px] font-semibold text-slate-700">{title}</span>
        <div className="flex items-center gap-2">
          <span className="tnum text-xs text-slate-400">{lines.length} 条</span>
          <Button size="sm" variant="ghost" icon={<Copy size={12} />} onClick={onCopy}>
            复制
          </Button>
        </div>
      </div>
      <div className="max-h-[260px] overflow-auto p-3 font-mono text-[12.5px] leading-6">
        {lines.length ? (
          lines.map((line, i) => (
            <div key={`${i}-${line}`} className={tone === 'red' ? 'text-red-600' : 'text-emerald-600'}>
              {prefix} {line}
            </div>
          ))
        ) : (
          <span className="text-slate-400">（无）</span>
        )}
      </div>
    </div>
  )
}

export function ToolCompare() {
  const toast = useToast()

  const [aText, setAText] = useState('')
  const [bText, setBText] = useState('')
  const [result, setResult] = useState<CompareResult | null>(null)
  const [loading, setLoading] = useState(false)

  const onlyALines = useMemo(() => toLines(result?.only_a || ''), [result])
  const onlyBLines = useMemo(() => toLines(result?.only_b || ''), [result])

  /** 对齐后的两列（同一行位置上的 A / B 值，缺失一侧为空） */
  const alignedRows = useMemo<AlignedRow[]>(() => {
    if (!result) return []
    if (!result.aligned_a && !result.aligned_b) return []
    const a = result.aligned_a.split('\n')
    const b = result.aligned_b.split('\n')
    const len = Math.max(a.length, b.length)
    return Array.from({ length: len }, (_, i) => ({ a: a[i] || '', b: b[i] || '' }))
  }, [result])

  async function importFile(target: 'a' | 'b') {
    const files = await pickFile('.txt,.csv,.log')
    const file = files?.[0]
    if (!file) return
    try {
      const raw = await file.text()
      // 兼容换行与逗号/制表符分隔，自动拆成每行一个
      const vals = raw
        .split(/\r?\n|[,，\t]/)
        .map((s) => s.trim())
        .filter(Boolean)
      const uniq = Array.from(new Set(vals)).join('\n')
      if (target === 'a') setAText(uniq)
      else setBText(uniq)
      toast.success(`已导入 ${file.name}，识别 ${vals.length} 行`)
    } catch {
      toast.error('文件读取失败')
    }
  }

  async function compare() {
    setLoading(true)
    try {
      const res = await api.post<CompareResult>('/api/tools/compare', { a: aText, b: bText })
      setResult(res.data || null)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '对比失败')
    } finally {
      setLoading(false)
    }
  }

  async function copyLines(lines: string[]) {
    if (!lines.length) {
      toast.info('没有可复制的内容')
      return
    }
    try {
      await navigator.clipboard.writeText(lines.join('\n'))
      toast.success('已复制')
    } catch {
      toast.error('复制失败')
    }
  }

  const alignedColumns: Column<AlignedRow>[] = [
    {
      key: 'a',
      title: '文件 A（基线 / 旧清单）',
      render: (row) =>
        row.a ? (
          <span className={row.b ? 'break-all text-slate-700' : 'break-all font-medium text-red-600'}>
            {row.a}
          </span>
        ) : (
          <span className="text-slate-300">—</span>
        ),
    },
    {
      key: 'b',
      title: '文件 B（当前 / 新清单）',
      render: (row) =>
        row.b ? (
          <span className={row.a ? 'break-all text-slate-700' : 'break-all font-medium text-emerald-600'}>
            {row.b}
          </span>
        ) : (
          <span className="text-slate-300">—</span>
        ),
    },
    {
      key: 'status',
      title: '状态',
      width: 90,
      render: (row) => {
        if (row.a && row.b) return <Badge tone="amber">共有</Badge>
        if (row.a) return <Badge tone="red">仅 A 有</Badge>
        return <Badge tone="green">仅 B 有</Badge>
      },
    },
  ]

  return (
    <div className="flex flex-col gap-4">
      <PageIntro
        icon={<Icon size={18} />}
        title="A/B 文件对比"
        description="把两份「每行一个值」的名单按行比对，快速发现新增与消失的资产。"
      />

      <Card>
        <CardHeader title="A/B 文件对比（资产基线比对）" />
        <CardBody className="flex flex-col gap-4">
          <div className="rounded-md border border-line border-l-2 border-l-primary bg-slate-50 px-3.5 py-3 text-[13px] leading-6 text-slate-600">
            <b className="text-slate-800">这是什么：</b>
            把两份“每行一个值”的名单（域名 / IP / URL / 资产名等）按行比对，自动算出：
            <br />
            <Badge tone="red">仅 A 有</Badge> 在 B 中消失（疑似已下线 / 被删除）·
            <Badge tone="blue">仅 B 有</Badge> 相比 A 新增 ·<Badge tone="amber">共有</Badge> 两边都在。
            <br />
            <b className="text-slate-800">典型用法：</b>
            本期资产清单 vs 上期基线，快速发现<b>新增资产</b>与<b>消失资产</b>；也可用于两份名单去重、查漏。
            支持直接粘贴，或点下方按钮导入 .txt/.csv（自动按行/逗号拆分）。
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <div className="flex flex-col gap-1.5">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-medium text-slate-600">文件 A（基线 / 旧清单）</span>
                <Button size="sm" variant="ghost" icon={<Upload size={13} />} onClick={() => importFile('a')}>
                  导入文件
                </Button>
              </div>
              <Textarea
                rows={10}
                value={aText}
                onChange={(e) => setAText(e.target.value)}
                placeholder="每行一个值，例如旧一期的域名清单"
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-medium text-slate-600">文件 B（当前 / 新清单）</span>
                <Button size="sm" variant="ghost" icon={<Upload size={13} />} onClick={() => importFile('b')}>
                  导入文件
                </Button>
              </div>
              <Textarea
                rows={10}
                value={bText}
                onChange={(e) => setBText(e.target.value)}
                placeholder="每行一个值，例如本期最新的域名清单"
              />
            </div>
          </div>

          <div>
            <Button variant="primary" icon={<Play size={14} />} loading={loading} onClick={compare}>
              开始对比
            </Button>
          </div>
        </CardBody>
      </Card>

      {result ? (
        <Card>
          <CardHeader
            title="对比结果"
            description="按行对齐后，左侧为基线、右侧为当前清单，红色表示消失、绿色表示新增。"
          />
          <CardBody className="flex flex-col gap-4">
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone="blue">A 共 {result.a_count} 条</Badge>
              <Badge tone="green">B 共 {result.b_count} 条</Badge>
              <Badge tone="amber">相同 {result.common_count} 条</Badge>
              <Badge tone="red">仅 A 有 {onlyALines.length} 条</Badge>
              <Badge tone="sky">仅 B 有 {onlyBLines.length} 条</Badge>
            </div>

            <div className="grid gap-4 lg:grid-cols-2">
              <DiffPanel
                title="仅 A 存在"
                lines={onlyALines}
                prefix="-"
                tone="red"
                onCopy={() => copyLines(onlyALines)}
              />
              <DiffPanel
                title="仅 B 存在"
                lines={onlyBLines}
                prefix="+"
                tone="green"
                onCopy={() => copyLines(onlyBLines)}
              />
            </div>

            <div className="overflow-hidden rounded-md border border-line">
              <DataTable
                columns={alignedColumns}
                rows={alignedRows}
                rowKey={(row, i) => `${i}-${row.a}-${row.b}`}
                empty={<EmptyState title="暂无数据" description="两份清单均为空，请先填写后再对比" />}
                rowClassName={(row) => {
                  if (row.a && row.b) return undefined
                  return row.a ? 'bg-red-50/40' : 'bg-emerald-50/40'
                }}
              />
            </div>
          </CardBody>
        </Card>
      ) : null}
    </div>
  )
}
