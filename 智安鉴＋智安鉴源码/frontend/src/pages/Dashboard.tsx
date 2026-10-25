import { useCallback } from 'react'
import { Link } from 'react-router-dom'
import { Boxes, Building2, FileText, Globe, KeyRound, ShieldAlert, Sparkles, Upload } from 'lucide-react'
import { Card, CardBody, CardHeader } from '@/components/ui/card'
import { DataTable, type Column } from '@/components/ui/table'
import { SeverityBadge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { ErrorBlock, LoadingBlock } from '@/components/ui/states'
import { api } from '@/lib/api'
import { LIFECYCLE_LABEL, LIFECYCLE_ORDER, SEVERITY_DOT, SEVERITY_LABEL, SEVERITY_ORDER, fmtTime } from '@/lib/format'
import { useQuery } from '@/lib/use-query'
import { cn } from '@/lib/cn'

interface ReportRow {
  id: number
  unit_name: string
  vul_name: string
  severity: string
  created_at: string
}

interface DashboardData {
  stats: { units: number; domains: number; vulns: number; reports: number; templates: number }
  severity: Record<string, number>
  recent: ReportRow[]
  recent_units: Array<{ enterprise_name: string; city?: string; business_status?: string }>
  monthly_trend: Array<{ month: string; count: number }>
  top_units: Array<{ unit_name: string; count: number }>
  lifecycle: Record<string, number>
  closed_rate: number
  handling_rate: number
}

const STAT_CARDS = [
  { key: 'units', label: '单位资产', icon: Building2, tone: 'bg-blue-50 text-blue-600 border-blue-100' },
  { key: 'domains', label: '域名资产', icon: Globe, tone: 'bg-sky-50 text-sky-600 border-sky-100' },
  { key: 'vulns', label: '漏洞知识库', icon: ShieldAlert, tone: 'bg-amber-50 text-amber-600 border-amber-100' },
  { key: 'reports', label: '漏洞报告', icon: FileText, tone: 'bg-red-50 text-red-600 border-red-100' },
  { key: 'templates', label: '报告模板', icon: Boxes, tone: 'bg-violet-50 text-violet-600 border-violet-100' },
] as const

const LC_TONE: Record<string, string> = {
  open: 'border-red-100 bg-red-50 text-red-700',
  fixing: 'border-blue-100 bg-blue-50 text-blue-700',
  fixed: 'border-amber-100 bg-amber-50 text-amber-700',
  verified: 'border-emerald-100 bg-emerald-50 text-emerald-700',
}

const LC_BAR: Record<string, string> = {
  open: 'bg-red-500',
  fixing: 'bg-blue-500',
  fixed: 'bg-amber-500',
  verified: 'bg-emerald-500',
}

function Donut({ data }: { data: Record<string, number> }) {
  const items = SEVERITY_ORDER.map((k) => ({ key: k, value: data[k] || 0 })).filter((x) => x.value > 0)
  const total = items.reduce((sum, x) => sum + x.value, 0)
  const r = 54
  const c = 2 * Math.PI * r
  let offset = 0

  if (!total) {
    return <div className="py-10 text-center text-[13px] text-slate-400">暂无数据</div>
  }

  return (
    <div className="flex items-center gap-4">
      <div className="relative h-[132px] w-[132px] shrink-0">
        <svg viewBox="0 0 132 132" className="h-full w-full -rotate-90">
          <circle cx="66" cy="66" r={r} fill="none" stroke="#f1f5f9" strokeWidth="14" />
          {items.map((it) => {
            const len = (it.value / total) * c
            const el = (
              <circle
                key={it.key}
                cx="66"
                cy="66"
                r={r}
                fill="none"
                stroke={SEVERITY_DOT[it.key]}
                strokeWidth="14"
                strokeDasharray={`${len} ${c - len}`}
                strokeDashoffset={-offset}
              />
            )
            offset += len
            return el
          })}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="tnum text-[22px] font-semibold leading-none text-slate-900">{total}</span>
          <span className="mt-1 text-[11px] text-slate-400">漏洞总数</span>
        </div>
      </div>
      <ul className="min-w-0 flex-1 space-y-1.5">
        {items.map((it) => (
          <li key={it.key} className="flex items-center gap-2 text-[12.5px]">
            <span className="h-2 w-2 shrink-0 rounded-sm" style={{ background: SEVERITY_DOT[it.key] }} />
            <span className="min-w-0 flex-1 truncate text-slate-600">{SEVERITY_LABEL[it.key]}</span>
            <span className="tnum font-medium text-slate-800">{it.value}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

export function Dashboard() {
  const load = useCallback(async () => {
    const res = await api.get<DashboardData>('/api/dashboard')
    return res.data as DashboardData
  }, [])
  const { data, loading, error, reload } = useQuery(load, [load])

  const columns: Column<ReportRow>[] = [
    {
      key: 'unit_name',
      title: '单位',
      render: (r) => <span className="block max-w-[180px] truncate">{r.unit_name}</span>,
    },
    {
      key: 'vul_name',
      title: '漏洞',
      render: (r) => <span className="block max-w-[220px] truncate text-slate-600">{r.vul_name}</span>,
    },
    { key: 'severity', title: '等级', width: 76, render: (r) => <SeverityBadge severity={r.severity} /> },
    {
      key: 'created_at',
      title: '时间',
      width: 150,
      render: (r) => <span className="text-xs text-slate-400">{fmtTime(r.created_at)}</span>,
    },
  ]

  if (loading && !data) return <LoadingBlock />
  if (error && !data) return <ErrorBlock message={error} onRetry={reload} />
  if (!data) return null

  const lifecycle = data.lifecycle || {}
  const trendMax = Math.max(...(data.monthly_trend || []).map((t) => t.count), 1)
  const topMax = Math.max(...(data.top_units || []).map((t) => t.count), 1)

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
        {STAT_CARDS.map(({ key, label, icon: Icon, tone }) => (
          <div key={key} className="flex items-center gap-3 rounded-lg border border-line bg-surface p-3.5 shadow-card">
            <span className={cn('flex h-9 w-9 shrink-0 items-center justify-center rounded-md border', tone)}>
              <Icon size={17} />
            </span>
            <div className="min-w-0">
              <div className="tnum text-[22px] font-semibold leading-tight text-slate-900">
                {data.stats[key]}
              </div>
              <div className="truncate text-xs text-slate-500">{label}</div>
            </div>
          </div>
        ))}
      </div>

      <Card>
        <CardHeader
          title="漏洞处置全生命周期闭环"
          description="按「待整改 → 整改中 → 已修复待复测 → 复测通过」跟踪闭环进度"
          actions={
            <Link to="/reports">
              <Button size="sm" variant="ghost">
                前往处置 →
              </Button>
            </Link>
          }
        />
        <CardBody className="flex flex-col gap-4">
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            {LIFECYCLE_ORDER.map((key) => (
              <div key={key} className={cn('rounded-md border px-3.5 py-3', LC_TONE[key])}>
                <div className="tnum text-[24px] font-semibold leading-none">{lifecycle[key] || 0}</div>
                <div className="mt-1.5 text-xs text-slate-600">{LIFECYCLE_LABEL[key]}</div>
              </div>
            ))}
          </div>
          <div className="grid gap-3 md:grid-cols-2">
            {[
              { label: '处置推进率（整改中 + 已修复 + 已闭环）', value: data.handling_rate || 0, bar: 'bg-blue-500' },
              { label: '复测闭环率（已复测通过 / 全部报告）', value: data.closed_rate || 0, bar: 'bg-emerald-500' },
            ].map((item) => (
              <div key={item.label}>
                <div className="mb-1.5 flex items-center justify-between text-xs text-slate-600">
                  <span className="truncate">{item.label}</span>
                  <span className="tnum font-semibold text-slate-800">{item.value}%</span>
                </div>
                <div className="h-2 overflow-hidden rounded-full bg-slate-100">
                  <div className={cn('h-full rounded-full transition-all', item.bar)} style={{ width: `${item.value}%` }} />
                </div>
              </div>
            ))}
          </div>
        </CardBody>
      </Card>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_340px]">
        <div className="flex min-w-0 flex-col gap-4">
          <Card>
            <CardHeader
              title="最近报告"
              actions={
                <Link to="/reports">
                  <Button size="sm" variant="ghost">
                    查看全部
                  </Button>
                </Link>
              }
            />
            <DataTable
              columns={columns}
              rows={data.recent || []}
              rowKey={(r) => r.id}
              empty={<div className="py-6 text-center text-[13px] text-slate-400">暂无报告，前往「报告管理」创建第一份报告</div>}
            />
          </Card>

          <Card>
            <CardHeader title="近 6 个月报告趋势" />
            <CardBody>
              {(data.monthly_trend || []).length === 0 ? (
                <div className="py-8 text-center text-[13px] text-slate-400">近 6 个月暂无报告</div>
              ) : (
                <div className="flex h-40 items-end gap-3">
                  {data.monthly_trend.map((t) => (
                    <div key={t.month} className="flex min-w-0 flex-1 flex-col items-center gap-1.5">
                      <span className="tnum text-[11px] font-medium text-slate-600">{t.count}</span>
                      <div
                        className="w-full max-w-[46px] rounded-t bg-primary/90 transition-all hover:bg-primary"
                        style={{ height: `${Math.max(6, (t.count / trendMax) * 120)}px`, backgroundColor: 'var(--primary)' }}
                        title={`${t.month}：${t.count} 份`}
                      />
                      <span className="text-[11px] text-slate-400">{t.month.slice(5)}月</span>
                    </div>
                  ))}
                </div>
              )}
            </CardBody>
          </Card>
        </div>

        <div className="flex min-w-0 flex-col gap-4">
          <Card>
            <CardHeader title="漏洞等级分布" />
            <CardBody>
              <Donut data={data.severity || {}} />
            </CardBody>
          </Card>

          <Card>
            <CardHeader title="报告数量 TOP 单位" />
            <CardBody>
              {(data.top_units || []).length === 0 ? (
                <div className="py-4 text-center text-[13px] text-slate-400">暂无数据</div>
              ) : (
                <ul className="flex flex-col gap-2.5">
                  {data.top_units.map((t, i) => (
                    <li key={`${t.unit_name}-${i}`}>
                      <div className="mb-1 flex items-center justify-between gap-2 text-[12.5px]">
                        <span className="min-w-0 truncate text-slate-600">
                          {i + 1}. {t.unit_name}
                        </span>
                        <span className="tnum font-medium text-slate-800">{t.count}</span>
                      </div>
                      <div className="h-1.5 overflow-hidden rounded-full bg-slate-100">
                        <div
                          className="h-full rounded-full"
                          style={{ width: `${(t.count / topMax) * 100}%`, backgroundColor: 'var(--primary)' }}
                        />
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </CardBody>
          </Card>

          <Card>
            <CardHeader title="快捷操作" />
            <CardBody className="flex flex-col gap-2">
              <Link to="/reports/ai">
                <Button variant="primary" block icon={<Sparkles size={14} />}>
                  AI 生成报告
                </Button>
              </Link>
              <Link to="/reports">
                <Button variant="secondary" block icon={<FileText size={14} />}>
                  新建漏洞报告
                </Button>
              </Link>
              <Link to="/units">
                <Button variant="secondary" block icon={<Upload size={14} />}>
                  批量导入单位
                </Button>
              </Link>
              <Link to="/tools/password">
                <Button variant="secondary" block icon={<KeyRound size={14} />}>
                  随机密码生成
                </Button>
              </Link>
            </CardBody>
          </Card>
        </div>
      </div>
    </div>
  )
}
