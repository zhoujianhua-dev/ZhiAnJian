import { useCallback, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { Download, FileText, Languages, Plus, Search, ShieldCheck } from 'lucide-react'
import { Card } from '@/components/ui/card'
import { DataTable, KV, type Column } from '@/components/ui/table'
import { Badge, LifecycleBadge, SeverityBadge } from '@/components/ui/badge'
import { Button, LinkButton } from '@/components/ui/button'
import { Field, Input, Select, Textarea } from '@/components/ui/field'
import { ImageZone } from '@/components/ui/image-zone'
import { Modal } from '@/components/ui/modal'
import { RichTextEditor } from '@/components/ui/rich-text'
import { EmptyState, ErrorBlock, LoadingBlock, Pagination } from '@/components/ui/states'
import { SuggestInput } from '@/components/ui/suggest-input'
import { useConfirm } from '@/components/ui/confirm'
import { useToast } from '@/components/ui/toast'
import { ApiError, api, downloadFile, ensureCsrf, pickFile } from '@/lib/api'
import { cn } from '@/lib/cn'
import {
  LIFECYCLE_LABEL,
  LIFECYCLE_ORDER,
  SEVERITY_LABEL,
  SEVERITY_ORDER,
  extractHost,
  fmtTime,
  lifecycleOf,
  type Lifecycle,
} from '@/lib/format'
import { useQuery } from '@/lib/use-query'

/* ============================================================
   报告管理：列表 / 表单 / 详情 / 处置闭环 / 导出 / 模板 / 质量体检
   ============================================================ */

interface ReportRow {
  id: number
  record_id?: string
  unit_name: string
  vul_name: string
  system_name?: string
  domain?: string
  address?: string
  description?: string
  severity: string
  harm?: string
  detail?: string
  suggestion?: string
  prove?: string
  detail_images?: unknown
  prove_images?: unknown
  lifecycle?: string
  lifecycle_cn?: string
  lifecycle_at?: string
  lifecycle_remark?: string
  status?: number
  created_at?: string
  updated_at?: string
}

interface ReportForm {
  unit_name: string
  system_name: string
  vul_name: string
  severity: string
  address: string
  domain: string
  description: string
  harm: string
  detail: string
  suggestion: string
  prove: string
  detail_images: string[]
  prove_images: string[]
}

interface UnitAssets {
  domains: string[]
  systems: string[]
  addresses: string[]
}

interface VulOption {
  id: number
  name: string
  severity: string
  description?: string
  harm?: string
  suggestion?: string
}

interface TemplateItem {
  id: number
  name: string
  filename: string
  is_default: number
  created_at?: string
  exists: boolean
  placeholders: string[]
}

interface ExportFile {
  filename: string
  size: number
  mtime: string
}

interface ExtractParagraph {
  idx: number
  text: string
  heading: boolean
  has_image: boolean
  suggest: string
}

interface ExtractPreview {
  token: string
  paragraphs: ExtractParagraph[]
  mapping: Record<string, string>
  fields: Array<{ key: string; name: string }>
  title_key: string
}

interface QaIssue {
  rule: string
  level: string
  msg: string
  weight: number
}

interface QaResult {
  id: number
  unit_name: string
  vul_name: string
  score: number
  level: string
  passed: boolean
  issues: QaIssue[]
  evidence_images: number
  detail_length: number
}

interface QaAll {
  results: QaResult[]
  total: number
  average_score: number
  passed_count: number
  issue_count: number
}

interface AiGrade {
  score?: number | null
  highlights?: string
  problems?: string[]
  suggestions?: string[]
  mock?: boolean
  error?: string
}

interface LifecycleTarget {
  id: number
  from: Lifecycle
  to: Lifecycle
  label: string
}

const LIMIT = 10

/** 模板支持的全部占位符（与 core/tpl_bootstrap.SUPPORTED_PLACEHOLDERS 一致） */
const PH_FIELDS = [
  '单位名称',
  '漏洞名称',
  '系统名称',
  '域名',
  '漏洞地址',
  '漏洞描述',
  '检测过程',
  '漏洞等级',
  '漏洞危害',
  '整改建议',
  '归属证明',
  '报告日期',
  '单位落款',
]

/** 合法流转路径（与 core/helpers.LIFECYCLE_TRANSITIONS 一致，非法流转由后端兜底拒绝） */
const LIFECYCLE_NEXT: Record<Lifecycle, Array<{ value: Lifecycle; label: string }>> = {
  open: [{ value: 'fixing', label: '开始整改' }],
  fixing: [
    { value: 'fixed', label: '提交整改' },
    { value: 'open', label: '退回' },
  ],
  fixed: [
    { value: 'verified', label: '复测通过' },
    { value: 'fixing', label: '复测退回' },
  ],
  verified: [{ value: 'fixed', label: '撤销复测' }],
}

const ISSUE_TONE: Record<string, string> = {
  critical: 'text-red-600',
  high: 'text-orange-600',
  medium: 'text-amber-600',
  low: 'text-slate-500',
}

function ph(name: string) {
  return `{{${name}}}`
}

function emptyForm(): ReportForm {
  return {
    unit_name: '',
    system_name: '',
    vul_name: '',
    // 与旧页面一致：新增时等级下拉默认落在第一项（严重）
    severity: 'critical',
    address: '',
    domain: '',
    description: '',
    harm: '',
    detail: '',
    suggestion: '',
    prove: '',
    detail_images: [],
    prove_images: [],
  }
}

/** 图片字段 → URL 数组（兼容数组、JSON 字符串、逗号分隔） */
function parseImgField(v: unknown): string[] {
  if (Array.isArray(v)) return v.map((x) => String(x))
  if (typeof v !== 'string' || !v.trim()) return []
  try {
    const arr: unknown = JSON.parse(v)
    if (Array.isArray(arr)) return arr.map((x) => String(x))
    return []
  } catch {
    return v
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
  }
}

function errText(e: unknown, fallback: string) {
  return e instanceof Error ? e.message : fallback
}

function scoreClass(score: number) {
  if (score >= 90) return 'text-emerald-600'
  if (score >= 75) return 'text-blue-600'
  if (score >= 60) return 'text-amber-600'
  return 'text-red-600'
}

function scoreBoxClass(score: number) {
  if (score >= 90) return 'border-emerald-200 bg-emerald-50 text-emerald-700'
  if (score >= 75) return 'border-blue-200 bg-blue-50 text-blue-700'
  if (score >= 60) return 'border-amber-200 bg-amber-50 text-amber-700'
  return 'border-red-200 bg-red-50 text-red-700'
}

function issueClass(level: string) {
  return ISSUE_TONE[level] || 'text-slate-500'
}

/* ============================================================
   主页面
   ============================================================ */

export function Reports() {
  const toast = useToast()
  const confirm = useConfirm()

  const [unitKw, setUnitKw] = useState('')
  const [vulKw, setVulKw] = useState('')
  const [qUnit, setQUnit] = useState('')
  const [qVul, setQVul] = useState('')
  const [severity, setSeverity] = useState('')
  const [lifecycle, setLifecycle] = useState('')
  const [page, setPage] = useState(1)
  const [selected, setSelected] = useState<Array<string | number>>([])

  const [formTarget, setFormTarget] = useState<{ id: number | null } | null>(null)
  const [detailId, setDetailId] = useState<number | null>(null)
  const [lifecycleTarget, setLifecycleTarget] = useState<LifecycleTarget | null>(null)
  const [exportOpen, setExportOpen] = useState(false)
  const [templateOpen, setTemplateOpen] = useState(false)
  const [qaOpen, setQaOpen] = useState(false)
  const [translatingNames, setTranslatingNames] = useState(false)
  const [qaOneId, setQaOneId] = useState<number | null>(null)

  const load = useCallback(async () => {
    const res = await api.get<ReportRow[]>('/api/reports', {
      page,
      limit: LIMIT,
      unitName: qUnit,
      vulName: qVul,
      severity,
      lifecycle,
    })
    return { rows: res.data || [], total: res.count || 0 }
  }, [page, qUnit, qVul, severity, lifecycle])

  const { data, loading, error, reload } = useQuery(load, [load])

  const rows = data?.rows || []
  const total = data?.total || 0

  // 与旧页面一致：列表重新加载（翻页 / 搜索 / 增删改后）勾选状态清空
  useEffect(() => {
    setSelected([])
  }, [data])

  function search() {
    setPage(1)
    setQUnit(unitKw.trim())
    setQVul(vulKw.trim())
  }

  /** 把报告里仍是英文的漏洞名称批量翻译为中文（英文原名保留在 vul_name_en） */
  async function translateNames() {
    const ok = await confirm({
      message: '把报告里仍是英文的漏洞名称批量翻译为中文？英文原名会保留，已是中文的报告不受影响。',
      confirmText: '开始翻译',
      danger: false,
    })
    if (!ok) return
    setTranslatingNames(true)
    try {
      const res = await api.post<{ updated: number }>('/api/report/translate-names')
      toast.success(res.msg || '翻译完成')
      await reload()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '翻译失败')
    } finally {
      setTranslatingNames(false)
    }
  }

  function openExport() {
    if (!selected.length && !rows.length) {
      toast.error('请先勾选要导出的报告')
      return
    }
    setExportOpen(true)
  }

  async function remove(r: ReportRow) {
    const ok = await confirm({ message: '确定删除该报告？', confirmText: '删除' })
    if (!ok) return
    try {
      const res = await api.post('/api/report/delete', { id: r.id })
      toast.success(res.msg || '已删除')
      if (rows.length === 1 && page > 1) setPage(page - 1)
      else await reload()
    } catch (e) {
      toast.error(errText(e, '删除失败'))
    }
  }

  const columns: Column<ReportRow>[] = [
    {
      key: 'id',
      title: 'ID',
      width: 64,
      render: (r) => <span className="tnum text-slate-500">{r.id}</span>,
    },
    {
      key: 'unit_name',
      title: '单位名称',
      render: (r) => (
        <span className="block max-w-[160px] truncate font-semibold text-slate-800">{r.unit_name}</span>
      ),
    },
    {
      key: 'system_name',
      title: '系统名称',
      render: (r) => <span className="block max-w-[120px] truncate text-slate-600">{r.system_name || '-'}</span>,
    },
    {
      key: 'vul_name',
      title: '漏洞名称',
      render: (r) => <span className="block max-w-[170px] truncate text-slate-700">{r.vul_name}</span>,
    },
    { key: 'severity', title: '等级', width: 76, render: (r) => <SeverityBadge severity={r.severity} /> },
    {
      key: 'lifecycle',
      title: '处置状态',
      width: 160,
      render: (r) => {
        const cur = lifecycleOf(r.lifecycle)
        return (
          <div className="flex flex-col gap-1">
            <LifecycleBadge lifecycle={cur} />
            <div className="flex flex-wrap gap-x-2 gap-y-1">
              {LIFECYCLE_NEXT[cur].map((n) => (
                <LinkButton
                  key={n.value}
                  className="text-xs"
                  onClick={() => setLifecycleTarget({ id: r.id, from: cur, to: n.value, label: n.label })}
                >
                  {n.label}
                </LinkButton>
              ))}
            </div>
          </div>
        )
      },
    },
    {
      key: 'updated_at',
      title: '更新时间',
      width: 150,
      render: (r) => <span className="text-xs text-slate-400">{fmtTime(r.updated_at)}</span>,
    },
    {
      key: 'actions',
      title: '操作',
      width: 180,
      render: (r) => (
        <div className="flex items-center gap-3 whitespace-nowrap">
          <LinkButton onClick={() => setDetailId(r.id)}>详情</LinkButton>
          <LinkButton onClick={() => setQaOneId(r.id)}>体检</LinkButton>
          <LinkButton onClick={() => setFormTarget({ id: r.id })}>编辑</LinkButton>
          <LinkButton danger onClick={() => remove(r)}>
            删除
          </LinkButton>
        </div>
      ),
    },
  ]

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <div className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-3">
          <Input
            value={unitKw}
            onChange={(e) => setUnitKw(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') search()
            }}
            placeholder="按单位搜索..."
            className="w-[180px]"
          />
          <Input
            value={vulKw}
            onChange={(e) => setVulKw(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') search()
            }}
            placeholder="按漏洞搜索..."
            className="w-[180px]"
          />
          <Select
            value={severity}
            onChange={(e) => {
              setSeverity(e.target.value)
              setPage(1)
            }}
            className="w-[120px]"
          >
            <option value="">全部等级</option>
            {SEVERITY_ORDER.map((s) => (
              <option key={s} value={s}>
                {SEVERITY_LABEL[s]}
              </option>
            ))}
          </Select>
          <Select
            value={lifecycle}
            onChange={(e) => {
              setLifecycle(e.target.value)
              setPage(1)
            }}
            className="w-[130px]"
          >
            <option value="">全部处置状态</option>
            {LIFECYCLE_ORDER.map((k) => (
              <option key={k} value={k}>
                {LIFECYCLE_LABEL[k]}
              </option>
            ))}
          </Select>
          <Button variant="primary" icon={<Search size={14} />} onClick={search}>
            搜索
          </Button>
          <span className="flex-1" />
          {selected.length ? (
            <span className="text-xs text-slate-500">
              已选 <span className="tnum font-medium text-slate-700">{selected.length}</span> 条
            </span>
          ) : null}
          <Button variant="warning" size="sm" icon={<Download size={14} />} onClick={openExport}>
            导出报告
          </Button>
          <Button
            variant="ghost"
            size="sm"
            icon={<Languages size={14} />}
            loading={translatingNames}
            onClick={() => void translateNames()}
          >
            翻译漏洞名
          </Button>
          <Button variant="ghost" size="sm" icon={<ShieldCheck size={14} />} onClick={() => setQaOpen(true)}>
            质量体检
          </Button>
          <Button variant="ghost" size="sm" icon={<FileText size={14} />} onClick={() => setTemplateOpen(true)}>
            模板管理
          </Button>
          <Button variant="primary" size="sm" icon={<Plus size={14} />} onClick={() => setFormTarget({ id: null })}>
            新增报告
          </Button>
        </div>

        <DataTable
          columns={columns}
          rows={rows}
          rowKey={(r) => r.id}
          loading={loading}
          selectable
          selectedKeys={selected}
          onSelectedChange={setSelected}
          empty={
            <EmptyState
              title="暂无报告"
              description="点击「+ 新增报告」手工录入，或使用「AI 智能生成」批量产出"
              action={
                <div className="flex items-center gap-2">
                  <Button size="sm" variant="primary" onClick={() => setFormTarget({ id: null })}>
                    新增报告
                  </Button>
                  <Link to="/reports/ai">
                    <Button size="sm" variant="secondary">
                      AI 智能生成
                    </Button>
                  </Link>
                </div>
              }
            />
          }
        />

        {error ? (
          <div className="border-t border-line">
            <ErrorBlock message={error} onRetry={reload} />
          </div>
        ) : null}

        <div className="border-t border-line px-4 py-3">
          <Pagination page={page} total={total} limit={LIMIT} onChange={setPage} />
        </div>
      </Card>

      {formTarget ? (
        <ReportFormDialog
          reportId={formTarget.id}
          onClose={() => setFormTarget(null)}
          onSaved={() => {
            setFormTarget(null)
            void reload()
          }}
        />
      ) : null}

      {detailId !== null ? (
        <ReportDetailDialog
          id={detailId}
          onClose={() => setDetailId(null)}
          onEdit={() => {
            setDetailId(null)
            setFormTarget({ id: detailId })
          }}
          onLifecycle={(t) => {
            setDetailId(null)
            setLifecycleTarget(t)
          }}
        />
      ) : null}

      {lifecycleTarget ? (
        <LifecycleDialog
          target={lifecycleTarget}
          onClose={() => setLifecycleTarget(null)}
          onDone={() => {
            setLifecycleTarget(null)
            void reload()
          }}
        />
      ) : null}

      {exportOpen ? (
        <ExportDialog
          selectedIds={selected.map((k) => Number(k))}
          pageIds={rows.map((r) => r.id)}
          onClose={() => setExportOpen(false)}
        />
      ) : null}

      {templateOpen ? <TemplateDialog onClose={() => setTemplateOpen(false)} /> : null}

      {qaOpen ? (
        <QaAllDialog
          onClose={() => setQaOpen(false)}
          onOpenOne={(id) => {
            setQaOpen(false)
            setQaOneId(id)
          }}
        />
      ) : null}

      {qaOneId !== null ? <QaOneDialog id={qaOneId} onClose={() => setQaOneId(null)} /> : null}
    </div>
  )
}

/* ============================================================
   新增 / 编辑报告
   ============================================================ */

function ReportFormDialog({
  reportId,
  onClose,
  onSaved,
}: {
  reportId: number | null
  onClose: () => void
  onSaved: () => void
}) {
  const toast = useToast()
  const [form, setForm] = useState<ReportForm>(emptyForm)
  const [loading, setLoading] = useState(reportId !== null)
  const [saving, setSaving] = useState(false)
  const [assets, setAssets] = useState<UnitAssets | null>(null)
  const [attribBusy, setAttribBusy] = useState(false)
  const domainAuto = useRef(true)
  const vulCache = useRef<Map<string, VulOption>>(new Map())

  // 编辑：读取报告详情回填
  useEffect(() => {
    if (reportId === null) return
    let alive = true
    void (async () => {
      try {
        const res = await api.get<ReportRow>('/api/report/detail', { id: reportId })
        const r = res.data
        if (!alive || !r) return
        domainAuto.current = false
        setForm({
          unit_name: r.unit_name || '',
          system_name: r.system_name || '',
          vul_name: r.vul_name || '',
          severity: r.severity || 'unknown',
          address: r.address || '',
          domain: r.domain || '',
          description: r.description || '',
          harm: r.harm || '',
          detail: r.detail || '',
          suggestion: r.suggestion || '',
          prove: r.prove || '',
          detail_images: parseImgField(r.detail_images),
          prove_images: parseImgField(r.prove_images),
        })
      } catch (e) {
        toast.error(errText(e, '读取报告失败'))
      } finally {
        if (alive) setLoading(false)
      }
    })()
    return () => {
      alive = false
    }
  }, [reportId, toast])

  // 单位名称 → 历史域名 / 系统自动带出
  useEffect(() => {
    const name = form.unit_name.trim()
    if (!name) {
      setAssets(null)
      return
    }
    let alive = true
    const timer = window.setTimeout(() => {
      void (async () => {
        try {
          const res = await api.get<UnitAssets>('/api/report/unit-assets', { unit_name: name })
          if (!alive) return
          const d = res.data
          setAssets(d || null)
          const domains = d?.domains || []
          // 域名框为空且该单位只有一个历史域名时自动带出
          if (domains.length === 1) {
            setForm((prev) => {
              if (prev.domain.trim()) return prev
              domainAuto.current = true
              return { ...prev, domain: domains[0] }
            })
          }
        } catch {
          if (alive) setAssets(null)
        }
      })()
    }, 400)
    return () => {
      alive = false
      window.clearTimeout(timer)
    }
  }, [form.unit_name])

  // 域名 → 反查所属单位（单位名称未填时自动带出）
  useEffect(() => {
    const dom = form.domain.trim()
    if (!dom || form.unit_name.trim()) return
    let alive = true
    const timer = window.setTimeout(() => {
      void (async () => {
        try {
          const res = await api.get<{ id: number; unitName: string } | null>('/api/unit/by-domain', {
            domain: dom,
          })
          const unitName = res.data?.unitName
          if (!alive || !unitName) return
          setForm((prev) => (prev.unit_name.trim() ? prev : { ...prev, unit_name: unitName }))
        } catch {
          /* 域名未登记时忽略 */
        }
      })()
    }, 400)
    return () => {
      alive = false
      window.clearTimeout(timer)
    }
  }, [form.domain, form.unit_name])

  const loadUnitOptions = useCallback(async (keyword: string) => {
    const res = await api.get<Array<{ id: number; enterprise_name: string }>>('/api/unit/search', {
      q: keyword,
    })
    return (res.data || []).map((u) => u.enterprise_name)
  }, [])

  const loadVulOptions = useCallback(async (keyword: string) => {
    const res = await api.get<VulOption[]>('/api/vulnerability/search', { q: keyword })
    const list = res.data || []
    list.forEach((v) => vulCache.current.set(v.name, v))
    return list.map((v) => v.name)
  }, [])

  function pickVul(name: string) {
    const v = vulCache.current.get(name)
    if (!v) return
    setForm((prev) => ({
      ...prev,
      vul_name: name,
      severity: v.severity || prev.severity,
      description: v.description || '',
      harm: v.harm || '',
      suggestion: v.suggestion || '',
    }))
  }

  // 漏洞地址 → 自动识别域名（用户手动改过域名后不再覆盖）
  function changeAddress(value: string) {
    const host = extractHost(value)
    setForm((prev) => {
      if (host && (!prev.domain.trim() || domainAuto.current)) {
        domainAuto.current = true
        return { ...prev, address: value, domain: host }
      }
      return { ...prev, address: value }
    })
  }

  function changeDomain(value: string) {
    domainAuto.current = false
    setForm((prev) => ({ ...prev, domain: value }))
  }

  async function loadLatestProve() {
    const domain = form.domain.trim()
    if (!domain) {
      toast.error('请先填写域名')
      return
    }
    try {
      const res = await api.get<{ prove?: string; prove_images?: string[] }>('/api/report/latest-prove', {
        domain,
      })
      const d = res.data
      const imgs = Array.isArray(d?.prove_images) ? d.prove_images : []
      setForm((prev) => ({ ...prev, prove: d?.prove || '', prove_images: imgs }))
      toast.success(
        imgs.length ? `已填入最近检测记录及 ${imgs.length} 张归属证明图片` : '已填入最近检测记录',
      )
    } catch (e) {
      toast.info(errText(e, '未找到历史记录'))
    }
  }

  async function autoAttrib() {
    const domain = form.domain.trim()
    const address = form.address.trim()
    if (!domain && !address) {
      toast.error('请先填写域名或漏洞地址')
      return
    }
    setAttribBusy(true)
    toast.info('正在读取目标站点页脚备案信息，约需 10~20 秒，请勿重复点击…')
    try {
      const res = await api.post<{ summary?: string; image_url?: string }>('/api/report/auto-attrib', {
        domain,
        address,
      })
      const d = res.data
      setForm((prev) => {
        const next = { ...prev }
        if (d?.summary) next.prove = d.summary
        if (d?.image_url && !prev.prove_images.includes(d.image_url)) {
          next.prove_images = [...prev.prove_images, d.image_url]
        }
        return next
      })
      toast.success(res.msg || '已自动完成归属取证')
    } catch (e) {
      if (e instanceof ApiError) toast.info(`${e.message}（可手动上传截图）`)
      else toast.error('自动取证失败，请手动上传归属截图')
    } finally {
      setAttribBusy(false)
    }
  }

  async function save() {
    const unitName = form.unit_name.trim()
    const vulName = form.vul_name.trim()
    if (!unitName || !vulName) {
      toast.error('单位名称与漏洞名称必填')
      return
    }
    setSaving(true)
    try {
      const body = {
        ...form,
        unit_name: unitName,
        vul_name: vulName,
        system_name: form.system_name.trim(),
        domain: form.domain.trim(),
        address: form.address.trim(),
      }
      const res = reportId
        ? await api.post('/api/report/update', { id: reportId, ...body })
        : await api.post('/api/report/add', body)
      toast.success(res.msg || '保存成功')
      onSaved()
    } catch (e) {
      toast.error(errText(e, '保存失败'))
    } finally {
      setSaving(false)
    }
  }

  const domains = assets?.domains || []
  const systems = (assets?.systems || []).slice(0, 5)

  return (
    <Modal
      open
      onClose={onClose}
      title={reportId ? `编辑报告 #${reportId}` : '新增报告'}
      size="xl"
      footer={
        <>
          <Button onClick={onClose}>取消</Button>
          <Button variant="primary" loading={saving} onClick={save}>
            保存
          </Button>
        </>
      }
    >
      {loading ? (
        <LoadingBlock text="正在读取报告…" />
      ) : (
        <div className="grid gap-3.5 sm:grid-cols-2">
          <Field label="单位名称" required>
            <SuggestInput
              value={form.unit_name}
              onChange={(v) => setForm((prev) => ({ ...prev, unit_name: v }))}
              load={loadUnitOptions}
              placeholder="支持模糊搜索自动匹配；填写已有单位可带出历史域名"
            />
          </Field>
          <Field label="系统名称">
            <Input
              value={form.system_name}
              onChange={(e) => setForm({ ...form, system_name: e.target.value })}
              placeholder="如：官网 / 后台管理系统"
            />
          </Field>
          <Field label="漏洞名称" required>
            <SuggestInput
              value={form.vul_name}
              onChange={(v) => setForm((prev) => ({ ...prev, vul_name: v }))}
              load={loadVulOptions}
              onPick={pickVul}
              placeholder="支持从漏洞库选择"
            />
          </Field>
          <Field label="漏洞等级">
            <Select
              value={form.severity}
              onChange={(e) => setForm({ ...form, severity: e.target.value })}
            >
              {SEVERITY_ORDER.map((s) => (
                <option key={s} value={s}>
                  {SEVERITY_LABEL[s]}
                </option>
              ))}
            </Select>
          </Field>
          <Field
            label={
              <>
                漏洞地址 / URL
                <span className="ml-1 text-[12px] font-normal text-sky-600">填好自动识别域名</span>
              </>
            }
          >
            <Input
              value={form.address}
              onChange={(e) => changeAddress(e.target.value)}
              placeholder="http(s)://、mqtt://、IP:端口 均可"
            />
          </Field>
          <Field label="域名">
            <Input
              value={form.domain}
              onChange={(e) => changeDomain(e.target.value)}
              placeholder="根据地址自动填入，可手动修改"
            />
          </Field>

          {domains.length || systems.length ? (
            <Field label="历史资产" className="sm:col-span-2" hint="点击可直接带出该单位的历史域名 / 系统名称">
              <div className="flex flex-wrap items-center gap-1.5">
                {domains.length ? <span className="text-xs text-slate-400">历史域名：</span> : null}
                {domains.map((d) => (
                  <button
                    key={`domain-${d}`}
                    type="button"
                    onClick={() => changeDomain(d)}
                    className="rounded border border-line bg-slate-50 px-1.5 py-px text-[11.5px] text-slate-600 transition-colors hover:border-primary hover:text-primary"
                  >
                    {d}
                  </button>
                ))}
                {systems.length ? <span className="ml-1.5 text-xs text-slate-400">历史系统：</span> : null}
                {systems.map((s) => (
                  <button
                    key={`system-${s}`}
                    type="button"
                    onClick={() => setForm((prev) => ({ ...prev, system_name: s }))}
                    className="rounded border border-line bg-slate-50 px-1.5 py-px text-[11.5px] text-slate-600 transition-colors hover:border-primary hover:text-primary"
                  >
                    {s}
                  </button>
                ))}
              </div>
            </Field>
          ) : null}

          <Field label="漏洞描述" className="sm:col-span-2">
            <Textarea
              rows={3}
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
            />
          </Field>
          <Field label="漏洞危害" className="sm:col-span-2">
            <Textarea rows={2} value={form.harm} onChange={(e) => setForm({ ...form, harm: e.target.value })} />
          </Field>
          <Field label="检测过程（富文本，可插图）" className="sm:col-span-2">
            <RichTextEditor
              value={form.detail}
              onChange={(html) => setForm((prev) => ({ ...prev, detail: html }))}
              placeholder="复现步骤、请求响应、命令输出等，可直接粘贴或插入截图…"
              minHeight={160}
            />
          </Field>
          <Field label="检测过程图片（多张，导出时附在“检测过程”之后）" className="sm:col-span-2">
            <ImageZone
              value={form.detail_images}
              onChange={(urls) => setForm((prev) => ({ ...prev, detail_images: urls }))}
              hint="检测过程截图 / 复现图（可多张，拖拽排序）"
            />
          </Field>
          <Field label="整改建议" className="sm:col-span-2">
            <Textarea
              rows={3}
              value={form.suggestion}
              onChange={(e) => setForm({ ...form, suggestion: e.target.value })}
            />
          </Field>
          <Field
            className="sm:col-span-2"
            label={
              <span className="flex flex-wrap items-center gap-x-1.5 gap-y-1">
                <span>归属证明（富文本，可插图）</span>
                <span className="text-slate-400">·</span>
                <LinkButton className="text-xs" onClick={loadLatestProve}>
                  按域名获取最近检测记录
                </LinkButton>
                <span className="text-slate-400">·</span>
                <LinkButton
                  className="text-xs text-emerald-600"
                  disabled={attribBusy}
                  onClick={autoAttrib}
                >
                  一键自动取证（截取官网页脚备案信息）
                </LinkButton>
              </span>
            }
          >
            <RichTextEditor
              value={form.prove}
              onChange={(html) => setForm((prev) => ({ ...prev, prove: html }))}
              placeholder="ICP 备案、公网安备、主体信息等归属说明…"
              minHeight={160}
            />
          </Field>
          <Field label="归属证明图片（多张，导出时附在“归属证明”之后）" className="sm:col-span-2">
            <ImageZone
              value={form.prove_images}
              onChange={(urls) => setForm((prev) => ({ ...prev, prove_images: urls }))}
              hint="归属证明截图：ICP / 备案 / 资产归属等（可多张）"
            />
          </Field>
        </div>
      )}
    </Modal>
  )
}

/* ============================================================
   报告详情
   ============================================================ */

function ReportDetailDialog({
  id,
  onClose,
  onEdit,
  onLifecycle,
}: {
  id: number
  onClose: () => void
  onEdit: () => void
  onLifecycle: (t: LifecycleTarget) => void
}) {
  const load = useCallback(async () => {
    const res = await api.get<ReportRow>('/api/report/detail', { id })
    return res.data as ReportRow
  }, [id])
  const { data, loading, error, reload } = useQuery(load, [load])

  const cur = lifecycleOf(data?.lifecycle)

  return (
    <Modal
      open
      onClose={onClose}
      title="报告详情"
      size="lg"
      footer={
        <>
          <Button onClick={onEdit}>编辑</Button>
          <Button variant="primary" onClick={onClose}>
            关闭
          </Button>
        </>
      }
    >
      {loading ? <LoadingBlock text="正在读取报告…" /> : null}
      {error ? <ErrorBlock message={error} onRetry={reload} /> : null}
      {data ? (
        <div>
          <KV label="单位名称">{data.unit_name}</KV>
          <KV label="系统名称">{data.system_name || '-'}</KV>
          <KV label="域名">{data.domain || '-'}</KV>
          <KV label="漏洞名称">{data.vul_name}</KV>
          <KV label="漏洞等级">
            <SeverityBadge severity={data.severity} />
          </KV>
          <KV label="漏洞地址">{data.address || '-'}</KV>
          <KV label="漏洞描述">{data.description || '-'}</KV>
          <KV label="漏洞危害">{data.harm || '-'}</KV>
          <KV label="整改建议">{data.suggestion || '-'}</KV>
          <KV label="处置状态">
            <div className="flex flex-col gap-1.5">
              <div className="flex flex-wrap items-center gap-2">
                <LifecycleBadge lifecycle={cur} />
                {data.lifecycle_at ? (
                  <span className="text-xs text-slate-400">最近操作：{data.lifecycle_at}</span>
                ) : null}
              </div>
              <div className="flex flex-wrap gap-x-3 gap-y-1">
                {LIFECYCLE_NEXT[cur].map((n) => (
                  <LinkButton
                    key={n.value}
                    onClick={() => onLifecycle({ id, from: cur, to: n.value, label: n.label })}
                  >
                    {n.label}
                  </LinkButton>
                ))}
              </div>
            </div>
          </KV>
          {data.lifecycle_remark ? (
            <KV label="整改轨迹">
              <span className="block whitespace-pre-wrap text-[13px] leading-7 text-slate-600">
                {data.lifecycle_remark}
              </span>
            </KV>
          ) : null}
        </div>
      ) : null}
    </Modal>
  )
}

/* ============================================================
   处置流转（含处置备注）
   ============================================================ */

function LifecycleDialog({
  target,
  onClose,
  onDone,
}: {
  target: LifecycleTarget
  onClose: () => void
  onDone: () => void
}) {
  const toast = useToast()
  const [remark, setRemark] = useState('')
  const [saving, setSaving] = useState(false)

  async function submit() {
    setSaving(true)
    try {
      const res = await api.post('/api/report/lifecycle', {
        id: target.id,
        lifecycle: target.to,
        remark: remark.trim(),
      })
      toast.success(res.msg || '处置状态已更新')
      onDone()
    } catch (e) {
      toast.error(errText(e, '处置流转失败'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={`处置流转 · ${target.label}`}
      size="sm"
      footer={
        <>
          <Button onClick={onClose}>取消</Button>
          <Button variant="primary" loading={saving} onClick={submit}>
            确认
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        <div className="flex items-center gap-2 rounded-md border border-line bg-slate-50 px-3 py-2.5 text-[13px] text-slate-700">
          <LifecycleBadge lifecycle={target.from} />
          <span className="text-slate-400">→</span>
          <LifecycleBadge lifecycle={target.to} />
          <span className="ml-auto text-xs text-slate-400">报告 #{target.id}</span>
        </div>
        <Field label="处置备注" hint="可选；会按时间追加到整改轨迹">
          <Textarea
            rows={3}
            value={remark}
            onChange={(e) => setRemark(e.target.value)}
            placeholder="如：已完成补丁升级并回归验证 / 复测发现同类问题仍存在…"
          />
        </Field>
      </div>
    </Modal>
  )
}

/* ============================================================
   导出（docx / PDF + 导出历史）
   ============================================================ */

const EXPORT_TEMPLATES = [
  { value: 'custom', label: '标准模板（Word 占位符自动填充，与原工具一致）' },
  { value: 'normal', label: '内置普通模板（漏洞详情排版）' },
  { value: 'gongwen', label: '网信办公文模板（隐患通报，仅单条）' },
  { value: 'summary', label: '汇总模板（多漏洞清单）' },
]

function ExportDialog({
  selectedIds,
  pageIds,
  onClose,
}: {
  selectedIds: number[]
  pageIds: number[]
  onClose: () => void
}) {
  const toast = useToast()
  const [format, setFormat] = useState<'docx' | 'pdf'>('docx')
  const [templateKey, setTemplateKey] = useState('custom')
  const [templateId, setTemplateId] = useState('')
  const [org, setOrg] = useState('')
  const [templates, setTemplates] = useState<TemplateItem[]>([])
  const [history, setHistory] = useState<ExportFile[]>([])
  const [histLoading, setHistLoading] = useState(true)
  const [busy, setBusy] = useState(false)

  const loadTemplates = useCallback(async () => {
    try {
      const res = await api.get<TemplateItem[]>('/api/report/templates')
      const list = res.data || []
      setTemplates(list)
      const def = list.find((t) => t.is_default)
      setTemplateId((prev) => prev || (def ? String(def.id) : ''))
    } catch {
      setTemplates([])
    }
  }, [])

  const loadHistory = useCallback(async () => {
    setHistLoading(true)
    try {
      const res = await api.get<ExportFile[]>('/api/report/exports')
      setHistory(res.data || [])
    } catch {
      setHistory([])
    } finally {
      setHistLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadTemplates()
    void loadHistory()
    void (async () => {
      try {
        const res = await api.get<{ export_org?: string }>('/api/settings/appearance')
        setOrg(res.data?.export_org || '')
      } catch {
        /* 读取落款单位失败不影响导出 */
      }
    })()
  }, [loadTemplates, loadHistory])

  const ids = selectedIds.length ? selectedIds : pageIds

  async function run() {
    if (format === 'pdf' && templateKey === 'custom') {
      toast.error('自定义模板暂仅支持 Word，请选择 PDF 内置模板或改用 Word')
      return
    }
    if (templateKey === 'gongwen' && ids.length !== 1) {
      toast.error('公文模板仅支持单条报告，请只勾选一条')
      return
    }
    setBusy(true)
    try {
      const endpoint = format === 'pdf' ? '/api/report/export-pdf' : '/api/report/export'
      const res = await api.post<unknown>(endpoint, {
        report_ids: ids,
        template_key: templateKey,
        template_id: templateKey === 'custom' ? templateId : '',
        org_footer: org.trim(),
      })
      const url = typeof res.url === 'string' ? res.url : ''
      if (!url) {
        toast.error('未获取到下载地址，请稍后重试')
        return
      }
      toast.success('报告生成成功，开始下载')
      downloadFile(url)
      await loadHistory()
    } catch (e) {
      toast.error(errText(e, '导出失败'))
    } finally {
      setBusy(false)
    }
  }

  const historyColumns: Column<ExportFile>[] = [
    {
      key: 'filename',
      title: '文件名',
      render: (f) => <span className="block max-w-[320px] truncate font-medium text-slate-800">{f.filename}</span>,
    },
    {
      key: 'size',
      title: '大小',
      width: 90,
      render: (f) => <span className="tnum text-slate-600">{(f.size / 1024).toFixed(1)} KB</span>,
    },
    {
      key: 'mtime',
      title: '导出时间',
      width: 150,
      render: (f) => <span className="text-xs text-slate-400">{fmtTime(f.mtime)}</span>,
    },
    {
      key: 'actions',
      title: '操作',
      width: 70,
      render: (f) => (
        <LinkButton onClick={() => downloadFile(`/api/report/download/${encodeURIComponent(f.filename)}`)}>
          下载
        </LinkButton>
      ),
    },
  ]

  return (
    <Modal
      open
      onClose={onClose}
      title="导出 Word 报告"
      size="lg"
      footer={
        <>
          <Button onClick={onClose}>取消</Button>
          <Button variant="warning" loading={busy} onClick={run}>
            生成并下载
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-4">
        <div className="grid gap-3.5 sm:grid-cols-2">
          <Field label="导出格式">
            <Select value={format} onChange={(e) => setFormat(e.target.value === 'pdf' ? 'pdf' : 'docx')}>
              <option value="docx">Word（.docx）</option>
              <option value="pdf">PDF（.pdf）</option>
            </Select>
          </Field>
          <Field label="导出模板">
            <Select value={templateKey} onChange={(e) => setTemplateKey(e.target.value)}>
              {EXPORT_TEMPLATES.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.label}
                </option>
              ))}
            </Select>
          </Field>
          {templateKey === 'custom' ? (
            <Field
              label={`选择 Word 模板（自动填充其中的 ${ph('占位符')}）`}
              className="sm:col-span-2"
              hint={format === 'pdf' ? '自定义模板暂仅支持 Word 导出' : undefined}
            >
              <Select value={templateId} onChange={(e) => setTemplateId(e.target.value)}>
                {templates.length ? (
                  templates.map((t) => (
                    <option key={t.id} value={String(t.id)}>
                      {t.name}
                      {t.is_default ? '（默认）' : ''}
                    </option>
                  ))
                ) : (
                  <option value="">暂无模板，请先到模板管理上传或下载标准模板</option>
                )}
              </Select>
            </Field>
          ) : null}
          <Field label="报告落款单位（可选）" className="sm:col-span-2">
            <Input
              value={org}
              onChange={(e) => setOrg(e.target.value)}
              placeholder="如：XX 网络安全测评中心"
            />
          </Field>
        </div>

        <div className="rounded-md border border-line bg-slate-50 px-3 py-2.5 text-xs leading-6 text-slate-600">
          将导出{' '}
          <b className="text-slate-800">
            {selectedIds.length
              ? `${selectedIds.length} 条`
              : `全部 ${pageIds.length} 条（当前列表；勾选可只导出指定报告）`}
          </b>
        </div>

        <div className="flex flex-col gap-2">
          <div className="flex items-center gap-2">
            <h4 className="flex-1 text-[13px] font-semibold text-slate-800">导出历史</h4>
            <Button size="sm" variant="ghost" loading={histLoading} onClick={() => void loadHistory()}>
              刷新
            </Button>
          </div>
          <div className="overflow-hidden rounded-md border border-line">
            <DataTable
              columns={historyColumns}
              rows={history}
              rowKey={(f) => f.filename}
              loading={histLoading}
              empty={<div className="py-6 text-center text-[13px] text-slate-400">暂无导出记录</div>}
            />
          </div>
        </div>
      </div>
    </Modal>
  )
}

/* ============================================================
   模板管理
   ============================================================ */

function TemplateDialog({ onClose }: { onClose: () => void }) {
  const toast = useToast()
  const confirm = useConfirm()
  const [list, setList] = useState<TemplateItem[]>([])
  const [loading, setLoading] = useState(true)
  const [name, setName] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [uploading, setUploading] = useState(false)
  const [extracting, setExtracting] = useState(false)
  const [preview, setPreview] = useState<ExtractPreview | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await api.get<TemplateItem[]>('/api/report/templates')
      setList(res.data || [])
    } catch (e) {
      toast.error(errText(e, '读取模板失败'))
      setList([])
    } finally {
      setLoading(false)
    }
  }, [toast])

  useEffect(() => {
    void load()
  }, [load])

  async function chooseFile() {
    const files = await pickFile('.docx')
    const f = files?.[0]
    if (f) setFile(f)
  }

  async function upload() {
    if (!name.trim() || !file) {
      toast.error('请填写名称并选择文件')
      return
    }
    const fd = new FormData()
    fd.append('name', name.trim())
    fd.append('file', file)
    // 文件上传不经过 api 的 CSRF 头注入，这里随表单一起提交（后端支持 form 里的 csrf_token）
    fd.append('csrf_token', await ensureCsrf())
    setUploading(true)
    try {
      const res = await api.upload<unknown>('/api/report/template/upload', fd)
      const raw = res.placeholders
      const count = Array.isArray(raw) ? raw.length : 0
      if (count) toast.success(`上传成功，识别到 ${count} 个可填充字段`)
      else toast.info(`上传成功，但未检测到 ${ph('占位符')}，该模板将按原样输出`)
      setName('')
      setFile(null)
      await load()
    } catch (e) {
      toast.error(errText(e, '上传失败'))
    } finally {
      setUploading(false)
    }
  }

  async function extract() {
    const files = await pickFile('.docx')
    const f = files?.[0]
    if (!f) return
    const fd = new FormData()
    fd.append('file', f)
    fd.append('csrf_token', await ensureCsrf())
    setExtracting(true)
    toast.info('正在解析报告段落并识别字段…')
    try {
      const res = await api.upload<ExtractPreview>('/api/report/template/extract-preview', fd)
      const d = res.data
      if (!d) {
        toast.error('解析失败，请重新导入')
        return
      }
      setPreview(d)
    } catch (e) {
      toast.error(errText(e, '解析失败'))
    } finally {
      setExtracting(false)
    }
  }

  async function setDefault(id: number) {
    try {
      const res = await api.post('/api/report/template/set-default', { id })
      toast.success(res.msg || '已设为默认模板')
      await load()
    } catch (e) {
      toast.error(errText(e, '设置默认模板失败'))
    }
  }

  async function remove(t: TemplateItem) {
    const ok = await confirm({ message: `确定删除模板「${t.name}」？`, confirmText: '删除' })
    if (!ok) return
    try {
      const res = await api.post('/api/report/template/delete', { id: t.id })
      toast.success(res.msg || '已删除')
      await load()
    } catch (e) {
      toast.error(errText(e, '删除失败'))
    }
  }

  const columns: Column<TemplateItem>[] = [
    {
      key: 'name',
      title: '模板名称',
      render: (t) => (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="font-semibold text-slate-800">{t.name}</span>
          {t.is_default ? <Badge tone="green">默认</Badge> : null}
          {t.exists ? null : <Badge tone="red">文件缺失</Badge>}
        </div>
      ),
    },
    {
      key: 'placeholders',
      title: '可自动填充字段',
      render: (t) =>
        t.placeholders?.length ? (
          <div className="flex max-w-[340px] flex-wrap gap-1">
            {t.placeholders.map((p) => (
              <Badge key={p} tone="violet">
                {ph(p)}
              </Badge>
            ))}
          </div>
        ) : (
          <span className="text-xs text-slate-400">未检测到占位符（静态模板）</span>
        ),
    },
    {
      key: 'created_at',
      title: '上传时间',
      width: 150,
      render: (t) => <span className="text-xs text-slate-400">{fmtTime(t.created_at)}</span>,
    },
    {
      key: 'actions',
      title: '操作',
      width: 160,
      render: (t) => (
        <div className="flex items-center gap-3 whitespace-nowrap">
          <LinkButton onClick={() => downloadFile(`/api/report/template/download?id=${t.id}`)}>下载</LinkButton>
          <LinkButton onClick={() => setDefault(t.id)}>设为默认</LinkButton>
          <LinkButton danger onClick={() => remove(t)}>
            删除
          </LinkButton>
        </div>
      ),
    },
  ]

  return (
    <>
      <Modal
        open
        onClose={onClose}
        title="报告模板管理"
        size="lg"
        footer={
          <Button variant="primary" onClick={onClose}>
            关闭
          </Button>
        }
      >
        <div className="flex flex-col gap-3.5">
          <div className="flex flex-wrap items-end gap-2.5">
            <Field label="模板名称" className="min-w-[200px] flex-1">
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="如：公司红头模板" />
            </Field>
            <Field label="上传 .docx 模板文件" className="min-w-[200px] flex-1">
              <Button variant="secondary" block onClick={() => void chooseFile()}>
                {file ? file.name : '选择 .docx 文件'}
              </Button>
            </Field>
            <Button variant="primary" loading={uploading} onClick={upload}>
              上传
            </Button>
          </div>

          <div className="rounded-md border border-dashed border-primary-line bg-primary-soft px-3.5 py-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[13px] font-semibold text-primary">方式二：导入一份现成报告 → 自动拆成模板 ✨</span>
              <span className="flex-1" />
              <Button variant="primary" size="sm" loading={extracting} onClick={() => void extract()}>
                导入并智能识别字段
              </Button>
            </div>
            <p className="mt-2 text-xs leading-6 text-slate-600">
              直接选一份你已有的送检报告（如“某单位存在某漏洞.docx”），系统自动识别“地址/描述/检测过程/等级/建议/归属”等段落并替换成占位符，
              <b>保留原排版字体</b>、自动剔除旧截图；识别结果可在下一步逐条核对修改。以后新增报告只填新内容，导出就与这份报告
              <b>版式一模一样</b>。
            </p>
          </div>

          <div className="rounded-md border border-line bg-slate-50 px-3 py-2.5 text-xs leading-6 text-slate-600">
            <b>用法：</b>在 Word 里用 <b>{ph('占位符')}</b> 标出要自动填充的位置，保存为 .docx 后上传；导出时选择该模板，系统自动把报告内容填进去（富文本换行、证据图片也会保留）。
            支持字段：
            <span className="text-primary">{PH_FIELDS.map(ph).join(' ')}</span>
            <br />
            <LinkButton
              className="text-xs font-semibold"
              onClick={() => downloadFile('/api/settings/builtin-template/guide')}
            >
              ⬇ 下载系统标准模板（含占位符，可直接改造成你的模板）
            </LinkButton>
          </div>

          <div className="overflow-hidden rounded-md border border-line">
            <DataTable
              columns={columns}
              rows={list}
              rowKey={(t) => t.id}
              loading={loading}
              empty={<div className="py-6 text-center text-[13px] text-slate-400">暂无模板</div>}
            />
          </div>
        </div>
      </Modal>

      {preview ? (
        <TemplateMapDialog
          preview={preview}
          onClose={() => setPreview(null)}
          onCreated={() => {
            setPreview(null)
            void load()
          }}
        />
      ) : null}
    </>
  )
}

/** 从成品报告生成模板：核对段落 → 字段映射 */
function TemplateMapDialog({
  preview,
  onClose,
  onCreated,
}: {
  preview: ExtractPreview
  onClose: () => void
  onCreated: () => void
}) {
  const toast = useToast()
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const [mapping, setMapping] = useState<Record<number, string>>(() => {
    const init: Record<number, string> = {}
    preview.paragraphs.forEach((p) => {
      if (p.suggest) init[p.idx] = p.suggest
    })
    return init
  })

  const visible = preview.paragraphs.filter((p) => (p.text && p.text.trim()) || p.has_image)

  async function build() {
    if (!name.trim()) {
      toast.error('请填写新模板名称')
      return
    }
    const clean: Record<string, string> = {}
    Object.entries(mapping).forEach(([idx, v]) => {
      if (v) clean[idx] = v
    })
    if (!Object.keys(clean).length) {
      toast.error('请至少为一个内容段选择对应字段')
      return
    }
    setBusy(true)
    try {
      const res = await api.post<unknown>('/api/report/template/build-from-doc', {
        token: preview.token,
        name: name.trim(),
        mapping: clean,
      })
      const raw = res.placeholders
      const count = Array.isArray(raw) ? raw.length : 0
      toast.success(`模板已生成，含 ${count} 个可自动填充字段`)
      onCreated()
    } catch (e) {
      toast.error(errText(e, '生成模板失败'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title="核对字段映射（自动识别，可手动调整）"
      size="lg"
      footer={
        <>
          <Button onClick={onClose}>取消</Button>
          <Button variant="primary" loading={busy} onClick={build}>
            生成模板
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        <div className="rounded-md border border-line bg-slate-50 px-3 py-2.5 text-xs leading-6 text-slate-600">
          系统已按章节标题自动猜测每段对应的字段（下拉已预选）。请<b>逐段核对</b>：内容段选择对应字段后会被替换成占位符；
          “漏洞描述/检测过程/建议”等若有多段内容，只需保留一个占位段，其余内容段也选同一字段（会自动合并、不重复）；
          成品里的旧截图会自动剔除，新报告导出时插入你上传的新图。
        </div>
        <Field label="新模板名称" className="max-w-[320px]">
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="如：浙江送检标准版" />
        </Field>
        <div className="overflow-hidden rounded-md border border-line">
          <div className="max-h-[46vh] overflow-y-auto">
            <table className="w-full border-collapse text-[13px]">
              <thead>
                <tr className="border-b border-line bg-slate-50">
                  <th className="w-10 px-3 py-2.5 text-xs font-medium text-slate-500">#</th>
                  <th className="px-3 py-2.5 text-left text-xs font-medium text-slate-500">报告原文段落</th>
                  <th className="w-[210px] px-3 py-2.5 text-left text-xs font-medium text-slate-500">映射为字段</th>
                </tr>
              </thead>
              <tbody>
                {visible.length === 0 ? (
                  <tr>
                    <td colSpan={3} className="px-3 py-6 text-center text-[13px] text-slate-400">
                      未解析到有效段落
                    </td>
                  </tr>
                ) : (
                  visible.map((p) => (
                    <tr key={p.idx} className="border-b border-line last:border-0">
                      <td className="px-3 py-2 text-center text-slate-400">{p.idx}</td>
                      <td className="px-3 py-2">
                        {p.has_image ? (
                          <Badge tone="sky" className="mr-1.5">
                            图
                          </Badge>
                        ) : p.heading ? (
                          <Badge tone="blue" className="mr-1.5">
                            标题
                          </Badge>
                        ) : null}
                        <span className="text-[12.5px] text-slate-700">{p.text || '［图片］'}</span>
                      </td>
                      <td className="px-3 py-2">
                        <Select
                          value={mapping[p.idx] || ''}
                          onChange={(e) =>
                            setMapping((prev) => {
                              const next = { ...prev }
                              if (e.target.value) next[p.idx] = e.target.value
                              else delete next[p.idx]
                              return next
                            })
                          }
                        >
                          <option value="">— 不替换（保留原文）—</option>
                          <option value={preview.title_key}>
                            {`标题：${ph('单位名称')}存在${ph('漏洞名称')}`}
                          </option>
                          {preview.fields.map((f) => (
                            <option key={f.key} value={f.key}>
                              {ph(f.name)}
                            </option>
                          ))}
                        </Select>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </Modal>
  )
}

/* ============================================================
   质量体检（全量）
   ============================================================ */

function QaAllDialog({ onClose, onOpenOne }: { onClose: () => void; onOpenOne: (id: number) => void }) {
  const load = useCallback(async () => {
    const res = await api.get<QaAll>('/api/report/qa')
    return res.data as QaAll
  }, [])
  const { data, loading, error, reload } = useQuery(load, [load])

  return (
    <Modal
      open
      onClose={onClose}
      title="报告质量体检"
      size="lg"
      footer={
        <Button variant="primary" onClick={onClose}>
          关闭
        </Button>
      }
    >
      {loading ? <LoadingBlock text="正在体检全部报告…" /> : null}
      {error ? <ErrorBlock message={error} onRetry={reload} /> : null}
      {data ? (
        <div>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            {[
              { label: '平均分', value: data.average_score, tone: scoreClass(data.average_score) },
              { label: '报告总数', value: data.total, tone: 'text-slate-900' },
              { label: '合格数', value: data.passed_count, tone: 'text-emerald-600' },
              { label: '问题项', value: data.issue_count, tone: 'text-orange-600' },
            ].map((s) => (
              <div key={s.label} className="rounded-md border border-line bg-slate-50 px-3 py-3 text-center">
                <div className={cn('tnum text-[26px] font-semibold leading-none', s.tone)}>{s.value}</div>
                <div className="mt-1.5 text-xs text-slate-500">{s.label}</div>
              </div>
            ))}
          </div>

          {data.results.length === 0 ? (
            <div className="py-6 text-center text-[13px] text-slate-400">暂无报告</div>
          ) : (
            <div className="mt-4 flex flex-col gap-2.5">
              {data.results.map((r) => (
                <div key={r.id} className="rounded-md border border-line px-3.5 py-3">
                  <div className="flex flex-wrap items-center gap-2.5">
                    <span className={cn('tnum w-[42px] text-[18px] font-semibold', scoreClass(r.score))}>
                      {r.score}
                    </span>
                    <Badge tone={r.passed ? 'green' : 'red'}>{r.level}</Badge>
                    <span className="min-w-0 flex-1 truncate text-[13px] font-semibold text-slate-800">
                      {r.unit_name} · {r.vul_name}
                    </span>
                    <LinkButton onClick={() => onOpenOne(r.id)}>详情/AI点评</LinkButton>
                  </div>
                  {r.issues.length ? (
                    <ul className="mt-1.5 list-disc pl-5">
                      {r.issues.map((i, idx) => (
                        <li key={`${i.rule}-${idx}`} className={cn('my-0.5 text-[12.5px]', issueClass(i.level))}>
                          {i.msg}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="mt-1.5 text-[12.5px] text-emerald-600">✓ 未发现问题</p>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      ) : null}
    </Modal>
  )
}

/* ============================================================
   质量体检（单条 + AI 点评）
   ============================================================ */

function QaOneDialog({ id, onClose }: { id: number; onClose: () => void }) {
  const toast = useToast()
  const load = useCallback(async () => {
    const res = await api.get<QaResult>('/api/report/qa-one', { id })
    return res.data as QaResult
  }, [id])
  const { data, loading, error, reload } = useQuery(load, [load])

  const [ai, setAi] = useState<AiGrade | null>(null)
  const [aiAsked, setAiAsked] = useState(false)
  const [aiLoading, setAiLoading] = useState(false)
  const [aiMsg, setAiMsg] = useState('')

  async function grade() {
    setAiAsked(true)
    setAiLoading(true)
    setAiMsg('')
    try {
      const res = await api.post<{ ai: AiGrade | null }>('/api/ai/grade', { id })
      setAi(res.data?.ai ?? null)
    } catch (e) {
      toast.error(errText(e, 'AI 点评失败'))
      setAiMsg(errText(e, 'AI 点评失败'))
    } finally {
      setAiLoading(false)
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title="单份报告体检"
      size="lg"
      footer={
        <>
          <Button variant="secondary" loading={aiLoading} onClick={grade}>
            🤖 AI 专家点评
          </Button>
          <Button variant="primary" onClick={onClose}>
            关闭
          </Button>
        </>
      }
    >
      {loading ? <LoadingBlock text="正在体检…" /> : null}
      {error ? <ErrorBlock message={error} onRetry={reload} /> : null}
      {data ? (
        <div className="flex flex-col gap-3.5">
          <div className="flex items-center gap-4">
            <div
              className={cn(
                'flex h-[74px] w-[74px] shrink-0 flex-col items-center justify-center rounded-md border',
                scoreBoxClass(data.score),
              )}
            >
              <span className="tnum text-[24px] font-semibold leading-none">{data.score}</span>
            </div>
            <div className="min-w-0">
              <div className="text-[15px] font-semibold text-slate-900">
                {data.unit_name} · {data.vul_name}
              </div>
              <div className="mt-1 text-[12.5px] text-slate-500">
                检测过程字数 {data.detail_length} · 证据图片 {data.evidence_images} 张
              </div>
            </div>
          </div>

          {data.issues.length ? (
            <ul className="list-disc pl-5">
              {data.issues.map((i, idx) => (
                <li key={`${i.rule}-${idx}`} className={cn('my-1 text-[13px]', issueClass(i.level))}>
                  {i.msg}
                </li>
              ))}
            </ul>
          ) : (
            <div className="text-[13px] text-emerald-600">✓ 各项检查通过，报告质量优秀</div>
          )}

          {aiAsked ? (
            <div className="rounded-md border border-line bg-slate-50 px-3.5 py-3">
              {aiLoading ? <LoadingBlock text="AI 点评中…" className="py-4" /> : null}
              {!aiLoading && aiMsg ? <p className="text-[13px] text-red-600">{aiMsg}</p> : null}
              {!aiLoading && !aiMsg && !ai ? (
                <p className="text-[13px] text-slate-600">
                  未配置 AI Key（可在系统设置配置，或使用模拟模式）
                </p>
              ) : null}
              {!aiLoading && !aiMsg && ai ? (
                <div className="flex flex-col gap-2 text-[13px] text-slate-700">
                  {ai.error ? <p className="text-red-600">{ai.error}</p> : null}
                  {ai.score != null ? <p className="font-semibold text-slate-900">AI 评分：{ai.score} 分</p> : null}
                  {ai.highlights ? (
                    <p>
                      <b>亮点：</b>
                      {ai.highlights}
                    </p>
                  ) : null}
                  {ai.problems?.length ? (
                    <div>
                      <b>问题：</b>
                      <ul className="my-1 list-disc pl-5">
                        {ai.problems.map((p, i) => (
                          <li key={`problem-${i}`}>{p}</li>
                        ))}
                      </ul>
                    </div>
                  ) : null}
                  {ai.suggestions?.length ? (
                    <div>
                      <b>改进建议：</b>
                      <ul className="my-1 list-disc pl-5">
                        {ai.suggestions.map((p, i) => (
                          <li key={`suggestion-${i}`}>{p}</li>
                        ))}
                      </ul>
                    </div>
                  ) : null}
                  {ai.mock ? <p className="text-[11px] text-slate-400">当前为模拟点评</p> : null}
                </div>
              ) : null}
            </div>
          ) : null}
        </div>
      ) : null}
    </Modal>
  )
}
