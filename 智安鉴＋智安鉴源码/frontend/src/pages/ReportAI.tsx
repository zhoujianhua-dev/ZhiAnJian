import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Download,
  Image as ImageIcon,
  Loader2,
  Plus,
  Radar,
  Sparkles,
  Upload,
  X,
} from 'lucide-react'
import { Card, CardBody, CardHeader, PageIntro } from '@/components/ui/card'
import { Button, LinkButton } from '@/components/ui/button'
import { Badge, SeverityBadge, TagChip } from '@/components/ui/badge'
import { Checkbox, Field, Input, Select, Textarea } from '@/components/ui/field'
import { ImageZone } from '@/components/ui/image-zone'
import { Modal } from '@/components/ui/modal'
import { RichTextEditor } from '@/components/ui/rich-text'
import { SuggestInput } from '@/components/ui/suggest-input'
import { DataTable, type Column } from '@/components/ui/table'
import { EmptyState } from '@/components/ui/states'
import { useConfirm } from '@/components/ui/confirm'
import { useToast } from '@/components/ui/toast'
import { api, downloadFile, pickFile } from '@/lib/api'
import { SEVERITY_LABEL, SEVERITY_ORDER, extractHost, fmtTime } from '@/lib/format'
import { useQuery } from '@/lib/use-query'

/* ==================== 类型（字段与后端保持一致，snake_case） ==================== */

interface AssetInfo {
  unit_name: string
  system_name: string
  domain: string
  address: string
}

interface UnitAssets {
  domains?: string[]
  systems?: string[]
  addresses?: string[]
}

/** 原始发现数据（Nuclei / Burp / 手工格式，结构不定，整体透传给后端） */
interface RawFinding {
  source?: string
  data?: Record<string, unknown>
  [key: string]: unknown
}

interface Finding {
  vul_name: string
  severity: string
  address: string
  description: string
  harm: string
  detail: string
  detail_images: string[]
  suggestion: string
  prove: string
  prove_images: string[]
}

/** 入库/导出时附加资产字段（与旧页面 collectFindings 一致） */
interface ReportPayload extends Finding {
  unit_name: string
  system_name: string
  domain: string
}

interface KnowledgeItem {
  name?: string | null
  severity?: string | null
}

/** /api/ai/retrieve-knowledge 返回的本地漏洞库条目 */
interface KnowledgeVuln {
  name?: string
  severity?: string
  description?: string
  harm?: string
  suggestion?: string
}

interface AnalyzeData {
  findings?: Finding[]
  knowledge?: KnowledgeItem[]
  mock?: boolean
}

interface AiConfigData {
  base_url?: string
  model?: string
  api_key_masked?: string
  configured?: boolean
}

interface CompleteData {
  description?: string
  harm?: string
  suggestion?: string
  detail?: string
}

interface ParseData {
  source?: string
  source_cn?: string
  count?: number
  severity_stats_cn?: Record<string, number>
  findings?: RawFinding[]
}

interface TemplateItem {
  id: number
  name: string
  is_default?: number
  filename?: string
}

interface ExportFile {
  filename: string
  size: number
  mtime: string
}

interface ShellingAgent {
  name?: string
  role?: string
  status?: string
  progress?: number
  findings_count?: number
}

interface ShellingProgress {
  scan_id?: string
  status?: string
  status_cn?: string
  phase?: string
  message?: string
  finished?: boolean
  ok?: boolean
  sub_agents?: ShellingAgent[]
}

interface ShellingResult {
  scan_id?: string
  target?: string
  scan_type_cn?: string
  status?: string
  status_cn?: string
  llm_summary?: string
  count?: number
  severity_stats_cn?: Record<string, number>
  findings?: RawFinding[]
}

interface ScanBanner {
  kind: 'parse' | 'scan' | 'handoff'
  count: number
  sourceCn?: string
  target?: string
  scanTypeCn?: string
  stats: Array<{ label: string; count: number }>
  llmSummary?: string
  hint: string
}

const EMPTY_ASSET: AssetInfo = { unit_name: '', system_name: '', domain: '', address: '' }

const SCAN_FILE_ACCEPT = '.json,.jsonl,.xml,.txt,.log,.csv'

const TEMPLATE_OPTIONS: Array<{ value: string; label: string }> = [
  { value: 'normal', label: '普通模板' },
  { value: 'gongwen', label: '网信办公文模板（隐患通报，仅单条）' },
  { value: 'summary', label: '汇总模板' },
  { value: 'custom', label: '自定义模板' },
]

const EMPTY_FINDING: Finding = {
  vul_name: '',
  severity: 'unknown',
  address: '',
  description: '',
  harm: '',
  detail: '',
  detail_images: [],
  suggestion: '',
  prove: '',
  prove_images: [],
}

function statsToArray(stats?: Record<string, number> | null): Array<{ label: string; count: number }> {
  return Object.entries(stats || {}).map(([label, count]) => ({ label, count: Number(count) || 0 }))
}

/** AI 返回的漏洞条目 → 页面可编辑结构（补齐图片字段） */
function normalizeFinding(raw: Finding): Finding {
  return {
    vul_name: raw.vul_name || '',
    severity: raw.severity || 'unknown',
    address: raw.address || '',
    description: raw.description || '',
    harm: raw.harm || '',
    detail: raw.detail || '',
    detail_images: Array.isArray(raw.detail_images) ? raw.detail_images : [],
    suggestion: raw.suggestion || '',
    prove: raw.prove || '',
    prove_images: Array.isArray(raw.prove_images) ? raw.prove_images : [],
  }
}

function readAsDataUrl(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(typeof reader.result === 'string' ? reader.result : '')
    reader.onerror = () => reject(new Error('读取图片失败'))
    reader.readAsDataURL(file)
  })
}

function errText(e: unknown, fallback: string) {
  return e instanceof Error && e.message ? e.message : fallback
}

/* ==================== ① 目标资产信息 ==================== */

interface AssetFormProps {
  value: AssetInfo
  unitAssets: UnitAssets | null
  loadUnits: (keyword: string) => Promise<string[]>
  onChange: (patch: Partial<AssetInfo>) => void
  onAddressChange: (v: string) => void
  onDomainChange: (v: string) => void
  onPickDomain: (v: string) => void
  onPickSystem: (v: string) => void
  onPickAddress: (v: string) => void
}

function AssetForm({
  value,
  unitAssets,
  loadUnits,
  onChange,
  onAddressChange,
  onDomainChange,
  onPickDomain,
  onPickSystem,
  onPickAddress,
}: AssetFormProps) {
  const domains = unitAssets?.domains || []
  const systems = unitAssets?.systems || []
  const addresses = unitAssets?.addresses || []

  return (
    <div className="grid gap-3.5 sm:grid-cols-2">
      <Field label="单位名称">
        <SuggestInput
          value={value.unit_name}
          onChange={(v) => onChange({ unit_name: v })}
          load={loadUnits}
          placeholder="XX 科技有限公司（填已有单位可带出历史域名）"
        />
      </Field>
      <Field label="系统名称">
        <Input
          value={value.system_name}
          onChange={(e) => onChange({ system_name: e.target.value })}
          placeholder="官网/门户网站"
        />
      </Field>
      <Field
        label={
          <>
            漏洞地址 / URL
            <span className="ml-1 text-xs font-normal text-primary">自动识别域名</span>
          </>
        }
      >
        <Input
          value={value.address}
          onChange={(e) => onAddressChange(e.target.value)}
          placeholder="http(s)://、mqtt://、IP:端口 均可"
        />
      </Field>
      <Field label="域名">
        <Input
          value={value.domain}
          onChange={(e) => onDomainChange(e.target.value)}
          placeholder="根据地址自动填入，可手动修改"
        />
      </Field>

      {domains.length || systems.length || addresses.length ? (
        <div className="flex flex-wrap items-center gap-1.5 sm:col-span-2">
          {domains.length ? (
            <>
              <span className="text-xs text-slate-400">历史域名：</span>
              {domains.map((d) => (
                <button key={d} type="button" onClick={() => onPickDomain(d)} title="点击填入域名">
                  <TagChip>{d}</TagChip>
                </button>
              ))}
            </>
          ) : null}
          {systems.length ? (
            <>
              <span className="ml-1.5 text-xs text-slate-400">历史系统：</span>
              {systems.slice(0, 5).map((s) => (
                <button key={s} type="button" onClick={() => onPickSystem(s)} title="点击填入系统名称">
                  <TagChip>{s}</TagChip>
                </button>
              ))}
            </>
          ) : null}
          {addresses.length ? (
            <>
              <span className="ml-1.5 text-xs text-slate-400">历史地址：</span>
              {addresses.slice(0, 5).map((a) => (
                <button key={a} type="button" onClick={() => onPickAddress(a)} title="点击填入漏洞地址">
                  <TagChip>{a}</TagChip>
                </button>
              ))}
            </>
          ) : null}
        </div>
      ) : null}
    </div>
  )
}

/* ==================== 扫描结果横幅 ==================== */

function ScanBannerView({ banner }: { banner: ScanBanner }) {
  return (
    <div className="rounded-md border border-blue-200 bg-blue-50 px-3.5 py-2.5 text-[13px] text-slate-700">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1.5">
        <span>
          {banner.kind === 'parse' ? (
            <>
              识别为 <b>{banner.sourceCn}</b> 格式，解析出 <b className="tnum">{banner.count}</b> 条记录
            </>
          ) : null}
          {banner.kind === 'scan' ? (
            <>
              已获取目标 <b>{banner.target}</b> 的{banner.scanTypeCn || '扫描'}结果，共{' '}
              <b className="tnum">{banner.count}</b> 条
            </>
          ) : null}
          {banner.kind === 'handoff' ? (
            <>
              已从「AI 漏洞扫描」带入目标 <b>{banner.target || '-'}</b> 的扫描结果，共{' '}
              <b className="tnum">{banner.count}</b> 条
            </>
          ) : null}
        </span>
        {banner.stats.map((s) => (
          <Badge key={s.label} tone="blue">
            {s.label} × {s.count}
          </Badge>
        ))}
      </div>
      <p className="mt-1 text-xs text-slate-500">{banner.hint}</p>
      {banner.llmSummary ? <p className="mt-1 text-xs text-violet-700">AI 摘要：{banner.llmSummary}</p> : null}
    </div>
  )
}

/* ==================== ③ 单条漏洞编辑器 ==================== */

interface FindingEditorProps {
  index: number
  value: Finding
  onChange: (patch: Partial<Finding>) => void
  onRemove: () => void
}

function FindingEditor({ index, value, onChange, onRemove }: FindingEditorProps) {
  return (
    <div className="overflow-hidden rounded-lg border border-line">
      <div className="flex flex-wrap items-center gap-2 border-b border-line bg-slate-50 px-3 py-2">
        <Badge tone="blue">漏洞 {index + 1}</Badge>
        <Input
          value={value.vul_name}
          onChange={(e) => onChange({ vul_name: e.target.value })}
          placeholder="漏洞名称"
          className="min-w-[160px] flex-1 bg-white"
        />
        <div className="w-[110px] shrink-0">
          <Select value={value.severity} onChange={(e) => onChange({ severity: e.target.value })}>
            {SEVERITY_ORDER.map((s) => (
              <option key={s} value={s}>
                {SEVERITY_LABEL[s]}
              </option>
            ))}
          </Select>
        </div>
        <LinkButton danger onClick={onRemove}>
          删除
        </LinkButton>
      </div>

      <div className="flex flex-col gap-3 p-3">
        <Field label="漏洞地址">
          <Input value={value.address} onChange={(e) => onChange({ address: e.target.value })} />
        </Field>
        <Field label="漏洞描述">
          <Textarea rows={3} value={value.description} onChange={(e) => onChange({ description: e.target.value })} />
        </Field>
        <Field label="危害分析">
          <Textarea rows={2} value={value.harm} onChange={(e) => onChange({ harm: e.target.value })} />
        </Field>
        <Field label="检测过程（富文本，可插图）">
          <div className="flex flex-col gap-2">
            <RichTextEditor
              value={value.detail}
              onChange={(html) => onChange({ detail: html })}
              minHeight={120}
              placeholder="检测过程：支持加粗、列表、代码与插图…"
            />
            <ImageZone
              value={value.detail_images}
              onChange={(urls) => onChange({ detail_images: urls })}
              hint="检测过程图片（多张，导出附在检测过程后）"
            />
          </div>
        </Field>
        <Field label="整改建议">
          <Textarea rows={3} value={value.suggestion} onChange={(e) => onChange({ suggestion: e.target.value })} />
        </Field>
        <Field label="归属证明（富文本，可插图）">
          <div className="flex flex-col gap-2">
            <RichTextEditor
              value={value.prove}
              onChange={(html) => onChange({ prove: html })}
              minHeight={100}
              placeholder="归属证明：支持加粗、列表、代码与插图…"
            />
            <ImageZone
              value={value.prove_images}
              onChange={(urls) => onChange({ prove_images: urls })}
              hint="归属证明图片（多张，导出附在归属证明之后）"
            />
          </div>
        </Field>
      </div>
    </div>
  )
}

/* ==================== 发起漏洞扫描（内置扫描引擎） ==================== */

interface ShellingScanModalProps {
  open: boolean
  defaultTarget: string
  /** 当前表单里的所属单位/系统：随扫描任务记录，后续可在「最近扫描」里直接加入报告管理 */
  unitName?: string
  systemName?: string
  onClose: () => void
  onApplied: (data: ShellingResult) => void
}

function ShellingScanModal({ open, defaultTarget, unitName = '', systemName = '', onClose, onApplied }: ShellingScanModalProps) {
  const toast = useToast()
  const [target, setTarget] = useState(defaultTarget)
  const [remark, setRemark] = useState('')
  const [scanId, setScanId] = useState('')
  const [progress, setProgress] = useState<ShellingProgress | null>(null)
  const [starting, setStarting] = useState(false)
  const [error, setError] = useState('')
  const appliedRef = useRef(false)

  // 每次打开重置为初始态，目标默认取当前漏洞地址 / 域名
  useEffect(() => {
    if (!open) return
    setTarget(defaultTarget)
    setRemark('')
    setScanId('')
    setProgress(null)
    setStarting(false)
    setError('')
    appliedRef.current = false
  }, [open, defaultTarget])

  const finish = useCallback(
    async (id: string, data: ShellingProgress) => {
      if (!data.ok) {
        toast.error('扫描未成功完成：' + (data.status_cn || data.status || '未知状态'))
        return
      }
      if (appliedRef.current) return
      appliedRef.current = true
      try {
        const res = await api.get<ShellingResult>(`/api/scanner/shelling/result/${encodeURIComponent(id)}`)
        const result = res.data
        if (!result) {
          toast.error('获取结果失败：未返回数据')
          return
        }
        onApplied(result)
      } catch (e) {
        toast.error('获取结果失败：' + errText(e, '未知错误'))
      }
    },
    [onApplied, toast],
  )

  // 轮询扫描进度（2.5s 一次，完成后拉取结果；关闭弹窗即停止轮询）
  useEffect(() => {
    if (!scanId || !open) return
    let stopped = false
    let busy = false
    let timer = 0
    const tick = async () => {
      if (busy || stopped) return
      busy = true
      try {
        const res = await api.get<ShellingProgress>(`/api/scanner/shelling/status/${encodeURIComponent(scanId)}`)
        if (stopped) return
        const data = res.data
        if (!data) {
          setError('查询进度失败')
          return
        }
        setProgress(data)
        if (data.finished) {
          stopped = true
          window.clearInterval(timer)
          await finish(scanId, data)
        }
      } catch (e) {
        if (!stopped) setError(errText(e, '查询进度失败'))
      } finally {
        busy = false
      }
    }
    timer = window.setInterval(() => {
      void tick()
    }, 2500)
    void tick()
    return () => {
      stopped = true
      window.clearInterval(timer)
    }
  }, [scanId, finish, open])

  async function start() {
    const t = target.trim()
    if (!t) {
      toast.error('请填写扫描目标')
      return
    }
    setStarting(true)
    setError('')
    setProgress(null)
    try {
      const res = await api.post<{ scan_id?: string }>('/api/scanner/shelling/start', {
        target: t,
        scan_type: 'full',
        unit_name: unitName.trim(),
        system_name: systemName.trim(),
        remark: remark.trim(),
      })
      const id = res.data?.scan_id
      if (!id) {
        setError('提交失败：未返回任务 ID')
        return
      }
      setScanId(id)
    } catch (e) {
      setError('提交失败：' + errText(e, '未知错误'))
    } finally {
      setStarting(false)
    }
  }

  const running = !!scanId && !(progress?.finished ?? false)
  const failed = !!progress?.finished && !progress?.ok

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="发起漏洞扫描"
      size="lg"
      footer={
        <>
          <Button variant="primary" loading={starting} disabled={running} onClick={start}>
            {running ? '扫描进行中...' : failed ? '重新扫描' : '开始扫描'}
          </Button>
          <Button variant="ghost" onClick={onClose}>
            关闭
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="扫描目标（域名 / IP / URL）" className="sm:col-span-2">
            <Input
              value={target}
              disabled={running}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="10.0.5.145 或 https://example.com"
            />
          </Field>
          <Field label="备注（可选）" className="sm:col-span-2">
            <Input
              value={remark}
              disabled={running}
              onChange={(e) => setRemark(e.target.value)}
              placeholder="智安鉴发起"
            />
          </Field>
        </div>

        {error ? <p className="text-[13px] text-red-600">{error}</p> : null}

        {starting && !scanId ? (
          <div className="flex items-center gap-2 text-[13px] text-primary">
            <Loader2 size={15} className="animate-spin" />
            正在提交扫描任务...
          </div>
        ) : null}

        {progress ? (
          <div className="rounded-md border border-blue-200 bg-blue-50 px-3.5 py-2.5 text-[13px]">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <b className="text-slate-800">{progress.status_cn || progress.status || '扫描中'}</b>
              <span className="text-xs text-slate-500">阶段：{progress.phase || '-'}</span>
            </div>
            {progress.message ? <p className="mt-0.5 text-xs text-slate-600">{progress.message}</p> : null}
            {(progress.sub_agents || []).map((agent, i) => {
              const pct = Math.max(0, Math.min(100, agent.progress || 0))
              return (
                <div key={`${agent.name || 'agent'}-${i}`} className="mt-2">
                  <div className="flex justify-between gap-2 text-xs text-slate-600">
                    <span className="min-w-0 truncate">
                      <b>{agent.name}</b> · {agent.role}
                    </span>
                    <span className="shrink-0 whitespace-nowrap">
                      {agent.status}
                      {agent.findings_count ? ` · 发现 ${agent.findings_count}` : ''}
                    </span>
                  </div>
                  <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-slate-200">
                    <div
                      className="h-full rounded-full transition-all"
                      style={{ width: `${pct}%`, backgroundColor: 'var(--primary)' }}
                    />
                  </div>
                </div>
              )
            })}
          </div>
        ) : null}

        <p className="text-xs leading-6 text-slate-500">
          扫描引擎已内置在系统中，无需任何配置：完成后结果会自动转换为漏洞数据填入下方输入框，
          可直接点击「分析预览」或「AI 分析并生成报告」。
        </p>
      </div>
    </Modal>
  )
}

/* ==================== 导出历史 ==================== */

function ExportHistory({ refreshKey }: { refreshKey: number }) {
  const load = useCallback(async () => {
    const res = await api.get<ExportFile[]>('/api/report/exports')
    return res.data || []
  }, [])

  const { data, loading, error, reload } = useQuery(load, [load])

  useEffect(() => {
    if (refreshKey > 0) void reload()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refreshKey])

  const columns: Column<ExportFile>[] = [
    {
      key: 'filename',
      title: '文件名',
      render: (f) => (
        <span className="block max-w-[420px] truncate font-medium text-slate-800" title={f.filename}>
          {f.filename}
        </span>
      ),
    },
    {
      key: 'size',
      title: '大小',
      width: 110,
      render: (f) => <span className="tnum text-slate-600">{(f.size / 1024).toFixed(1)} KB</span>,
    },
    {
      key: 'mtime',
      title: '导出时间',
      width: 170,
      render: (f) => <span className="text-xs text-slate-400">{fmtTime(f.mtime)}</span>,
    },
    {
      key: 'actions',
      title: '操作',
      width: 90,
      render: (f) => (
        <LinkButton onClick={() => downloadFile(`/api/report/download/${encodeURIComponent(f.filename)}`)}>
          下载
        </LinkButton>
      ),
    },
  ]

  return (
    <Card>
      <CardHeader
        title="导出历史"
        actions={
          <Button size="sm" variant="ghost" onClick={() => void reload()}>
            刷新
          </Button>
        }
      />
      {error ? <p className="px-4 pt-3 text-xs text-red-600">{error}</p> : null}
      <DataTable
        columns={columns}
        rows={data || []}
        rowKey={(f) => f.filename}
        loading={loading}
        empty={<EmptyState title="暂无导出记录" />}
      />
    </Card>
  )
}

/* ==================== 页面主体 ==================== */

export function ReportAI() {
  const toast = useToast()
  const confirm = useConfirm()

  // ① 目标资产信息
  const [asset, setAsset] = useState<AssetInfo>(EMPTY_ASSET)
  const [unitAssets, setUnitAssets] = useState<UnitAssets | null>(null)
  const domainAuto = useRef(true)
  const domainRef = useRef('')

  // ② 原始漏洞数据
  const [findingsText, setFindingsText] = useState('')
  const [rawText, setRawText] = useState('')
  const [evidenceImages, setEvidenceImages] = useState<string[]>([])
  const [detailImages, setDetailImages] = useState<string[]>([])
  const [proveImages, setProveImages] = useState<string[]>([])
  const [rawFindings, setRawFindings] = useState<RawFinding[]>([])
  const [parsing, setParsing] = useState(false)
  const [parsingName, setParsingName] = useState('')
  const [parseError, setParseError] = useState('')
  const [banner, setBanner] = useState<ScanBanner | null>(null)
  const [mock, setMock] = useState(false)

  // 生成设置
  const [templateKey, setTemplateKey] = useState('normal')
  const [templateId, setTemplateId] = useState('')
  const [orgFooter, setOrgFooter] = useState('')

  // ③ 分析结果
  const [findings, setFindings] = useState<Finding[]>([])
  const [resultOpen, setResultOpen] = useState(false)
  const [knowledge, setKnowledge] = useState<KnowledgeItem[]>([])
  const [generated, setGenerated] = useState<{ url: string; filename: string; count: number } | null>(null)
  const [historyKey, setHistoryKey] = useState(0)

  const [analyzing, setAnalyzing] = useState(false)
  const [generating, setGenerating] = useState(false)
  const [completing, setCompleting] = useState(false)
  const [summarizing, setSummarizing] = useState(false)
  const [savingAll, setSavingAll] = useState(false)
  const [exporting, setExporting] = useState(false)

  const [scanOpen, setScanOpen] = useState(false)
  const [completeData, setCompleteData] = useState<CompleteData | null>(null)
  const [summaryText, setSummaryText] = useState<string | null>(null)
  const [retrieving, setRetrieving] = useState(false)
  const [knowledgeHits, setKnowledgeHits] = useState<KnowledgeVuln[] | null>(null)

  /* ---------- 远程数据：AI 配置 / 报告模板 ---------- */

  const loadConfig = useCallback(async () => {
    const res = await api.get<AiConfigData>('/api/ai/config')
    return res.data || null
  }, [])
  const configQuery = useQuery(loadConfig, [loadConfig])

  const loadTemplates = useCallback(async () => {
    const res = await api.get<TemplateItem[]>('/api/report/templates')
    return res.data || []
  }, [])
  const templateQuery = useQuery(loadTemplates, [loadTemplates])
  const templates = templateQuery.data || []

  /* ---------- 资产信息：域名自动识别 + 同单位历史资产 ---------- */

  useEffect(() => {
    domainRef.current = asset.domain
  }, [asset.domain])

  const loadUnits = useCallback(async (keyword: string) => {
    const res = await api.get<Array<{ id: number; enterprise_name?: string }>>('/api/unit/search', { q: keyword })
    return (res.data || []).map((u) => u.enterprise_name || '').filter(Boolean)
  }, [])

  const loadUnitAssets = useCallback(async (name: string) => {
    if (!name) {
      setUnitAssets(null)
      return
    }
    try {
      const res = await api.get<UnitAssets>('/api/report/unit-assets', { unit_name: name })
      const d = res.data || null
      setUnitAssets(d)
      // 只有一个历史域名且当前域名框为空时，直接自动带出
      const domains = d?.domains || []
      if (domains.length === 1 && !domainRef.current.trim()) {
        domainAuto.current = true
        setAsset((a) => (a.domain.trim() ? a : { ...a, domain: domains[0] }))
      }
    } catch {
      setUnitAssets(null)
    }
  }, [])

  // 单位名称变化后（防抖 260ms）带出该单位的历史域名 / 系统
  useEffect(() => {
    const name = asset.unit_name.trim()
    if (!name) {
      setUnitAssets(null)
      return
    }
    const timer = window.setTimeout(() => {
      void loadUnitAssets(name)
    }, 260)
    return () => window.clearTimeout(timer)
  }, [asset.unit_name, loadUnitAssets])

  function patchAsset(patch: Partial<AssetInfo>) {
    setAsset((a) => ({ ...a, ...patch }))
  }

  function changeAddress(v: string) {
    setAsset((a) => {
      const next: AssetInfo = { ...a, address: v }
      const host = extractHost(v)
      if (host && (!a.domain.trim() || domainAuto.current)) {
        domainAuto.current = true
        next.domain = host
      }
      return next
    })
  }

  function changeDomain(v: string) {
    domainAuto.current = false
    patchAsset({ domain: v })
  }

  function pickDomain(v: string) {
    domainAuto.current = false
    patchAsset({ domain: v })
  }

  function pickSystem(v: string) {
    patchAsset({ system_name: v })
  }

  function pickAddress(v: string) {
    changeAddress(v)
  }

  /* ---------- 原始数据解析 ---------- */

  /** 读取「原始发现数据」文本框：JSON 数组优先，解析失败则整段作为手工文本 */
  function parseRawFindings(): RawFinding[] {
    const text = findingsText.trim()
    if (!text) return []
    try {
      const parsed: unknown = JSON.parse(text)
      if (Array.isArray(parsed)) return parsed as RawFinding[]
      return [{ source: 'manual', data: { title: '', description: text.slice(0, 800) } }]
    } catch {
      return [{ source: 'manual', data: { title: '', description: text.slice(0, 800) } }]
    }
  }

  async function importScanFile() {
    const files = await pickFile(SCAN_FILE_ACCEPT)
    const file = files?.[0]
    if (!file) return
    setParsing(true)
    setParsingName(file.name)
    setParseError('')
    setBanner(null)
    const fd = new FormData()
    fd.append('file', file)
    try {
      const res = await api.upload<ParseData>('/api/scanner/parse', fd)
      const d = res.data
      if (!d) {
        setParseError('解析失败：未返回数据')
        return
      }
      const list = d.findings || []
      setFindingsText(JSON.stringify(list, null, 2))
      setRawFindings(list)
      setBanner({
        kind: 'parse',
        count: d.count ?? list.length,
        sourceCn: d.source_cn || d.source || '',
        stats: statsToArray(d.severity_stats_cn),
        hint: '已填入下方数据框，可直接点击「分析预览」',
      })
      toast.success(`解析成功：${d.source_cn || d.source || ''}，${d.count ?? list.length} 条`)
    } catch (e) {
      setParseError('解析失败：' + errText(e, '未知错误'))
    } finally {
      setParsing(false)
      setParsingName('')
    }
  }

  async function loadSample() {
    if (asset.unit_name.trim() || findingsText.trim() || rawText.trim()) {
      const ok = await confirm({ message: '载入示例将覆盖当前已填写的资产与漏洞数据，确定继续？', confirmText: '载入示例' })
      if (!ok) return
    }
    domainAuto.current = false
    setAsset({
      unit_name: '演示科技有限公司',
      system_name: '业务管理系统',
      domain: 'demo-tech.com',
      address: 'https://demo-tech.com/login.php',
    })
    const sample: RawFinding[] = [
      {
        source: 'nuclei',
        data: {
          title: 'SQL 注入漏洞',
          severity: 'high',
          url: 'https://demo-tech.com/login.php',
          evidence: '参数 id 存在报错注入，AND 1=1 返回正常',
        },
      },
      {
        source: 'manual',
        data: {
          title: '敏感信息泄露',
          severity: 'medium',
          url: 'https://demo-tech.com/.git/config',
          evidence: '可直接访问 .git 目录，泄露源码',
        },
      },
    ]
    setFindingsText(JSON.stringify(sample, null, 2))
    setRawFindings(sample)
    setBanner(null)
    setParseError('')
    toast.success('示例数据已载入，可点击「分析预览」')
  }

  /** 扫描结果 / 扫描页带入结果统一填表 */
  function applyScanResult(d: ShellingResult, kind: 'scan' | 'handoff') {
    const list = d.findings || []
    setFindingsText(JSON.stringify(list, null, 2))
    setRawFindings(list)
    setParseError('')
    // 目标资产信息为空时自动带入，省去手工填写
    setAsset((a) => {
      if (a.address.trim() || !d.target) return a
      const addr = /^[a-z]+:\/\//i.test(d.target) ? d.target : `http://${d.target}`
      const host = extractHost(addr)
      const next: AssetInfo = { ...a, address: addr }
      if (host && !a.domain.trim()) {
        domainAuto.current = true
        next.domain = host
      }
      return next
    })
    setBanner({
      kind,
      count: d.count ?? list.length,
      target: d.target || '',
      scanTypeCn: d.scan_type_cn,
      stats: statsToArray(d.severity_stats_cn),
      llmSummary: d.llm_summary || undefined,
      hint: '已填入下方数据框，可直接点击「分析预览」或「AI 分析并生成报告」',
    })
    toast.success(
      kind === 'scan' ? `扫描完成，获取 ${d.count ?? list.length} 条漏洞数据` : `已带入扫描结果 ${list.length} 条`,
    )
  }

  // 「AI 漏洞扫描」页经 sessionStorage 带过来的结果
  useEffect(() => {
    let raw: string | null = null
    try {
      raw = sessionStorage.getItem('zhianjian_scan_handoff')
    } catch {
      return
    }
    if (!raw) return
    try {
      sessionStorage.removeItem('zhianjian_scan_handoff')
    } catch {
      /* 忽略 */
    }
    let parsed: unknown = null
    try {
      parsed = JSON.parse(raw)
    } catch {
      return
    }
    if (!parsed || typeof parsed !== 'object') return
    const d = parsed as ShellingResult
    if (!Array.isArray(d.findings)) return
    applyScanResult(d, 'handoff')
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  /* ---------- 证据图片（base64，随原始数据一起提交） ---------- */

  async function addEvidenceImages(files: File[]) {
    const imgs = files.filter((f) => f.type.startsWith('image/'))
    if (!imgs.length) return
    try {
      const list = await Promise.all(imgs.map(readAsDataUrl))
      const valid = list.filter(Boolean)
      if (valid.length) setEvidenceImages((prev) => [...prev, ...valid])
    } catch (e) {
      toast.error(errText(e, '读取图片失败'))
    }
  }

  async function pickEvidenceImages() {
    const files = await pickFile('image/*', true)
    if (files?.length) await addEvidenceImages(files)
  }

  /* ---------- AI 请求参数（与旧页面 getAiParams 一一对应） ---------- */

  function buildParams(raw: RawFinding[]) {
    return {
      asset_info: {
        unit_name: asset.unit_name.trim(),
        system_name: asset.system_name.trim(),
        domain: asset.domain.trim(),
        address: asset.address.trim(),
      },
      raw_findings: raw,
      raw_text: rawText,
      images: evidenceImages.map((base64) => ({ base64 })),
      detail_images: detailImages,
      prove_images: proveImages,
      template_key: templateKey,
      template_id: templateKey === 'custom' ? templateId : '',
      org_footer: orgFooter.trim(),
      // 模型配置统一由「系统设置 → AI 接口配置」提供，仅模拟模式用约定的 mock Key
      ...(mock ? { api_key: 'sk-test-mock' } : {}),
    }
  }

  /* ---------- 分析预览 ---------- */

  async function aiAnalyze() {
    const raw = parseRawFindings()
    setRawFindings(raw)
    setAnalyzing(true)
    try {
      const res = await api.post<AnalyzeData>('/api/ai/analyze', buildParams(raw))
      const d = res.data
      const list = (d?.findings || []).map(normalizeFinding)
      setFindings(list)
      setKnowledge(d?.knowledge || [])
      setGenerated(null)
      setResultOpen(true)
      if (d?.mock) toast.info('当前为模拟模式结果')
      else toast.success('AI 分析完成')
    } catch (e) {
      toast.error(errText(e, '分析失败'))
    } finally {
      setAnalyzing(false)
    }
  }

  /* ---------- 分析并生成报告 ---------- */

  async function aiGenerate() {
    const raw = parseRawFindings()
    setRawFindings(raw)
    setGenerating(true)
    try {
      const res = await api.post<unknown>('/api/ai/generate', buildParams(raw))
      const count = typeof res.records_created === 'number' ? res.records_created : 0
      const url = typeof res.url === 'string' ? res.url : ''
      const filename = typeof res.filename === 'string' ? res.filename : ''
      toast.success(`生成成功，共 ${count} 条报告`)
      setResultOpen(true)
      setGenerated({ url, filename, count })
      setHistoryKey((k) => k + 1)
      if (url) window.setTimeout(() => downloadFile(url), 600)
    } catch (e) {
      toast.error(errText(e, '生成失败'))
    } finally {
      setGenerating(false)
    }
  }

  /* ---------- AI 润色补全 ---------- */

  async function aiComplete() {
    setCompleting(true)
    try {
      const res = await api.post<CompleteData>('/api/ai/complete', {
        ...buildParams(rawFindings),
        existing_values: { vul_name: findingsText.trim().slice(0, 100) || 'SQL 注入漏洞' },
      })
      setCompleteData(res.data || {})
    } catch (e) {
      toast.error(errText(e, '润色失败'))
    } finally {
      setCompleting(false)
    }
  }

  /* ---------- AI 摘要 ---------- */

  async function aiSummary() {
    const raw = parseRawFindings()
    setRawFindings(raw)
    if (!raw.length && !rawText.trim()) {
      toast.error('请先填写漏洞数据')
      return
    }
    setSummarizing(true)
    try {
      const res = await api.post<{ summary?: string }>('/api/ai/summarize', {
        ...buildParams(raw),
        findings: raw.length ? raw : [{ source: 'text', data: { title: '漏洞' } }],
      })
      setSummaryText(res.data?.summary || '')
    } catch (e) {
      toast.error(errText(e, '摘要失败'))
    } finally {
      setSummarizing(false)
    }
  }

  /* ---------- 本地知识检索（不依赖 AI Key） ---------- */

  async function retrieveKnowledge() {
    const raw = parseRawFindings()
    setRawFindings(raw)
    const titles = raw.map((r) => {
      const d = (r.data || {}) as Record<string, unknown>
      return String(d.title || d.name || d.vul_name || '')
    })
    const query = [rawText.trim(), ...titles].filter(Boolean).join(' ').slice(0, 500)
    if (!query.trim()) {
      toast.error('请先填写漏洞数据')
      return
    }
    setRetrieving(true)
    try {
      const res = await api.post<KnowledgeVuln[]>('/api/ai/retrieve-knowledge', { query, top_k: 3 })
      setKnowledgeHits(res.data || [])
    } catch (e) {
      toast.error(errText(e, '检索失败'))
    } finally {
      setRetrieving(false)
    }
  }

  /* ---------- 结果条目增删改 ---------- */

  function updateFinding(index: number, patch: Partial<Finding>) {
    setFindings((list) => list.map((f, i) => (i === index ? { ...f, ...patch } : f)))
  }

  function addFinding() {
    setFindings((list) => [
      ...list,
      { ...EMPTY_FINDING, detail_images: [], prove_images: [], address: asset.address.trim() },
    ])
    setResultOpen(true)
  }

  async function removeFinding(index: number) {
    const name = findings[index]?.vul_name || '该漏洞'
    const ok = await confirm({ message: `确定删除「${name}」条目？删除后不可恢复。`, confirmText: '删除' })
    if (!ok) return
    setFindings((list) => list.filter((_, i) => i !== index))
  }

  /** 收集结果条目（仅保留已填漏洞名称的条目），附资产字段 */
  function collectFindings(): ReportPayload[] {
    return findings
      .map((f) => ({
        ...f,
        vul_name: f.vul_name.trim(),
        unit_name: asset.unit_name.trim(),
        system_name: asset.system_name.trim(),
        domain: asset.domain.trim(),
      }))
      .filter((f) => f.vul_name)
  }

  /* ---------- 保存到报告库 ---------- */

  async function saveAllFindings() {
    const list = collectFindings()
    setSavingAll(true)
    let ok = 0
    try {
      for (const f of list) {
        try {
          await api.post('/api/report/add', f)
          ok += 1
        } catch {
          /* 单条失败不阻断其余条目 */
        }
      }
    } finally {
      setSavingAll(false)
    }
    toast.success(`已保存 ${ok} 条报告到报告库`)
  }

  /* ---------- 导出 Word ---------- */

  async function exportFindings() {
    const list = collectFindings()
    if (!list.length) {
      toast.error('没有可导出的结果')
      return
    }
    setExporting(true)
    try {
      // 先入库拿到 id，再走统一导出
      const ids: number[] = []
      for (const f of list) {
        try {
          const res = await api.post<unknown>('/api/report/add', f)
          if (typeof res.id === 'number') ids.push(res.id)
        } catch {
          /* 单条失败不阻断导出 */
        }
      }
      const res = await api.post<unknown>('/api/report/export', {
        report_ids: ids,
        template_key: templateKey,
        template_id: templateKey === 'custom' ? templateId : '',
        org_footer: orgFooter.trim(),
      })
      const url = typeof res.url === 'string' ? res.url : ''
      toast.success('导出成功')
      setHistoryKey((k) => k + 1)
      if (url) window.setTimeout(() => downloadFile(url), 400)
    } catch (e) {
      toast.error(errText(e, '导出失败'))
    } finally {
      setExporting(false)
    }
  }

  /* ---------- 渲染 ---------- */

  const config = configQuery.data
  const configText = config?.configured
    ? `已配置 AI：${config.model || '默认模型'}${config.api_key_masked ? ` · ${config.api_key_masked}` : ''}`
    : '未配置 AI Key（可在系统设置配置，或使用模拟模式）'

  return (
    <div className="flex flex-col gap-4">
      <PageIntro
        icon={<Sparkles size={18} />}
        title="AI 赋能"
        description="粘贴 Nuclei / Burp / 手工记录等原始漏洞数据，AI 自动整理为规范报告并导出 Word"
        actions={
          <>
            <span className={config?.configured ? 'text-xs text-slate-500' : 'text-xs text-amber-600'}>
              {configQuery.error ? 'AI 配置状态读取失败' : configText}
            </span>
            <Checkbox label="模拟模式（无需 Key）" checked={mock} onChange={(e) => setMock(e.target.checked)} />
          </>
        }
      />

      {/* ① 目标资产信息 */}
      <Card>
        <CardHeader title="① 目标资产信息" />
        <CardBody>
          <AssetForm
            value={asset}
            unitAssets={unitAssets}
            loadUnits={loadUnits}
            onChange={patchAsset}
            onAddressChange={changeAddress}
            onDomainChange={changeDomain}
            onPickDomain={pickDomain}
            onPickSystem={pickSystem}
            onPickAddress={pickAddress}
          />
        </CardBody>
      </Card>

      {/* ② 原始漏洞数据 */}
      <Card>
        <CardHeader
          title="② 原始漏洞数据"
          actions={
            <>
              <Button size="sm" variant="primary" icon={<Radar size={14} />} onClick={() => setScanOpen(true)}>
                发起漏洞扫描
              </Button>
              <Button size="sm" variant="ghost" icon={<Upload size={14} />} loading={parsing} onClick={importScanFile}>
                导入扫描结果文件
              </Button>
              <Button size="sm" variant="ghost" onClick={loadSample}>
                载入示例
              </Button>
            </>
          }
        />
        <CardBody>
          <div className="flex flex-col gap-3.5">
            {parsing ? (
              <div className="flex items-center gap-2 text-[13px] text-primary">
                <Loader2 size={15} className="animate-spin" />
                正在智能解析 {parsingName} ...
              </div>
            ) : null}
            {parseError ? <p className="text-[13px] text-red-600">{parseError}</p> : null}
            {banner ? <ScanBannerView banner={banner} /> : null}

            <Field label="原始发现数据（JSON 数组，Nuclei/Burp/手工格式）">
              <Textarea
                rows={8}
                value={findingsText}
                onChange={(e) => setFindingsText(e.target.value)}
                placeholder='[{"source": "nuclei", "data": {"title": "SQL 注入", "severity": "high", "url": "https://...", "evidence": "..."}}]'
                className="font-mono text-xs"
              />
            </Field>

            <Field label="或直接粘贴文本描述（可选）">
              <Textarea
                rows={4}
                value={rawText}
                onChange={(e) => setRawText(e.target.value)}
                placeholder="用自然语言描述发现的漏洞情况，AI 将自动整理"
              />
            </Field>

            <Field label="证据图片（可选，随原始数据一起发给 AI 辅助分析）">
              <div className="flex flex-col gap-2">
                <div
                  tabIndex={0}
                  onPaste={(e) => {
                    const files = Array.from(e.clipboardData.files || [])
                    if (files.length) {
                      e.preventDefault()
                      void addEvidenceImages(files)
                    }
                  }}
                  className="flex flex-wrap items-center gap-2 rounded-md border border-dashed border-line-strong bg-slate-50 px-3 py-2.5 text-[13px] text-slate-500 focus:border-primary focus:outline-none"
                >
                  <Button size="sm" variant="secondary" icon={<ImageIcon size={14} />} onClick={pickEvidenceImages}>
                    选择图片
                  </Button>
                  <span className="text-xs">或点此处后按 Ctrl+V 粘贴截图（转 base64 随原始数据发送）</span>
                  {evidenceImages.length ? (
                    <span className="text-xs text-primary">已选 {evidenceImages.length} 张</span>
                  ) : null}
                </div>
                {evidenceImages.length ? (
                  <div className="flex flex-wrap gap-2">
                    {evidenceImages.map((src, index) => (
                      <div
                        key={`${index}-${src.slice(-24)}`}
                        className="group relative h-[76px] w-[100px] overflow-hidden rounded border border-line bg-white"
                      >
                        <img src={src} alt={`证据图片 ${index + 1}`} className="h-full w-full object-cover" />
                        <button
                          type="button"
                          onClick={() => setEvidenceImages((list) => list.filter((_, i) => i !== index))}
                          className="absolute right-1 top-1 flex h-4 w-4 items-center justify-center rounded-full bg-slate-900/60 text-white opacity-0 transition-opacity hover:bg-red-600 group-hover:opacity-100"
                          aria-label="移除图片"
                        >
                          <X size={10} />
                        </button>
                        <span className="absolute bottom-1 left-1 rounded bg-slate-900/60 px-1 text-[10px] text-white">
                          {index + 1}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : null}
              </div>
            </Field>

            <Field label="检测过程图片（可选，直接附到报告“检测过程”后，支持多张）">
              <ImageZone
                value={detailImages}
                onChange={setDetailImages}
                hint="检测过程图片（多张，导出附在检测过程之后）"
              />
            </Field>

            <Field label="归属证明图片（可选，直接附到报告“归属证明”后，支持多张）">
              <ImageZone
                value={proveImages}
                onChange={setProveImages}
                hint="归属证明图片（多张，导出附在归属证明之后）"
              />
            </Field>
          </div>

          {/* 生成设置：模板 / 自定义模板 / 单位落款 */}
          <div className="mt-3.5 grid gap-3 border-t border-line pt-3.5 sm:grid-cols-3">
            <Field label="报告模板">
              <Select value={templateKey} onChange={(e) => setTemplateKey(e.target.value)}>
                {TEMPLATE_OPTIONS.map((t) => (
                  <option key={t.value} value={t.value}>
                    {t.label}
                  </option>
                ))}
              </Select>
            </Field>
            {templateKey === 'custom' ? (
              <Field label="选择 Word 模板">
                <Select value={templateId} onChange={(e) => setTemplateId(e.target.value)}>
                  <option value="">默认自定义模板</option>
                  {templates.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name}
                      {t.is_default ? '（默认）' : ''}
                    </option>
                  ))}
                </Select>
              </Field>
            ) : null}
            <Field label="单位落款（可选）">
              <Input
                value={orgFooter}
                onChange={(e) => setOrgFooter(e.target.value)}
                placeholder="如：XX 网络安全测评中心"
              />
            </Field>
          </div>

          <div className="mt-3.5 flex flex-wrap items-center gap-2.5 border-t border-line pt-3.5">
            <Button variant="ghost" loading={analyzing} onClick={aiAnalyze}>
              {analyzing ? '分析中...' : '分析预览'}
            </Button>
            <Button
              variant="primary"
              icon={<Download size={14} />}
              loading={generating}
              onClick={aiGenerate}
            >
              {generating ? 'AI 生成中（约需 10-60 秒）...' : 'AI 分析并生成报告'}
            </Button>
            <Button variant="ghost" loading={completing} onClick={aiComplete}>
              AI 润色
            </Button>
            <Button variant="ghost" loading={summarizing} onClick={aiSummary}>
              AI 摘要
            </Button>
            <Button variant="ghost" loading={retrieving} onClick={retrieveKnowledge}>
              本地知识检索
            </Button>
            <span className="self-center text-xs text-slate-400">
              {mock ? '模拟模式：将返回演示数据，便于无 Key 联调' : ''}
            </span>
          </div>
        </CardBody>
      </Card>

      {/* ③ 分析结果 */}
      {resultOpen ? (
        <Card>
          <CardHeader
            title="③ 分析结果（可编辑后保存/导出）"
            actions={
              <>
                <Button size="sm" variant="ghost" icon={<Plus size={14} />} onClick={addFinding}>
                  新增漏洞
                </Button>
                <Button size="sm" variant="success" loading={savingAll} onClick={saveAllFindings}>
                  保存到报告库
                </Button>
                <Button size="sm" variant="warning" loading={exporting} onClick={exportFindings}>
                  导出 Word
                </Button>
              </>
            }
          />
          {knowledge.length ? (
            <div className="flex flex-wrap items-center gap-1.5 border-b border-violet-200 bg-violet-50 px-4 py-2.5 text-xs text-violet-800">
              <span>🧠 RAG 已参考本地漏洞库：</span>
              {knowledge.map((k, i) => (
                <Badge key={`${k.name || 'knowledge'}-${i}`} tone="violet">
                  {k.name || '未知漏洞'}（{k.severity || '未知'}）
                </Badge>
              ))}
            </div>
          ) : null}
          <CardBody className="flex flex-col gap-3.5">
            {generated ? (
              <div className="rounded-md border border-emerald-200 bg-emerald-50 px-4 py-3 text-[13px] text-emerald-800">
                <div>
                  已生成 <b className="tnum">{generated.count}</b> 条报告并导出 Word
                  {generated.filename ? <span className="ml-2 text-xs text-emerald-700">{generated.filename}</span> : null}
                </div>
                <div className="mt-2">
                  <Button
                    size="sm"
                    variant="primary"
                    icon={<Download size={14} />}
                    onClick={() => {
                      if (generated.url) downloadFile(generated.url)
                    }}
                  >
                    立即下载
                  </Button>
                </div>
              </div>
            ) : null}

            {findings.length === 0 ? (
              <EmptyState
                title="暂无分析结果"
                description="点击「分析预览」或「AI 分析并生成报告」获取结构化漏洞，也可手动新增条目"
                action={
                  <Button size="sm" variant="primary" icon={<Plus size={14} />} onClick={addFinding}>
                    新增漏洞
                  </Button>
                }
              />
            ) : (
              findings.map((f, index) => (
                <FindingEditor
                  key={index}
                  index={index}
                  value={f}
                  onChange={(patch) => updateFinding(index, patch)}
                  onRemove={() => void removeFinding(index)}
                />
              ))
            )}
          </CardBody>
        </Card>
      ) : null}

      <ExportHistory refreshKey={historyKey} />

      <ShellingScanModal
        open={scanOpen}
        defaultTarget={asset.address.trim() || asset.domain.trim()}
        unitName={asset.unit_name}
        systemName={asset.system_name}
        onClose={() => setScanOpen(false)}
        onApplied={(d) => {
          applyScanResult(d, 'scan')
          setScanOpen(false)
        }}
      />

      {/* AI 润色结果 */}
      <Modal
        open={completeData !== null}
        onClose={() => setCompleteData(null)}
        title="AI 润色结果"
        size="lg"
        footer={
          <Button variant="primary" onClick={() => setCompleteData(null)}>
            关闭
          </Button>
        }
      >
        {completeData ? (
          <div className="flex flex-col gap-3">
            <Field label="漏洞描述">
              <Textarea
                rows={3}
                value={completeData.description || ''}
                onChange={(e) => setCompleteData({ ...completeData, description: e.target.value })}
              />
            </Field>
            <Field label="危害分析">
              <Textarea
                rows={2}
                value={completeData.harm || ''}
                onChange={(e) => setCompleteData({ ...completeData, harm: e.target.value })}
              />
            </Field>
            <Field label="整改建议">
              <Textarea
                rows={3}
                value={completeData.suggestion || ''}
                onChange={(e) => setCompleteData({ ...completeData, suggestion: e.target.value })}
              />
            </Field>
          </div>
        ) : null}
      </Modal>

      {/* 本地知识检索结果 */}
      <Modal
        open={knowledgeHits !== null}
        onClose={() => setKnowledgeHits(null)}
        title="本地知识检索"
        size="lg"
        footer={
          <Button variant="primary" onClick={() => setKnowledgeHits(null)}>
            关闭
          </Button>
        }
      >
        {knowledgeHits && knowledgeHits.length ? (
          <div className="flex flex-col gap-2.5">
            {knowledgeHits.map((k, i) => (
              <div key={`${k.name || 'knowledge'}-${i}`} className="rounded-md border border-line px-3 py-2.5">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[13px] font-medium text-slate-800">{k.name || '未知漏洞'}</span>
                  <SeverityBadge severity={k.severity} />
                </div>
                {k.description ? (
                  <p className="mt-1 text-xs leading-6 text-slate-600">描述：{k.description}</p>
                ) : null}
                {k.harm ? <p className="mt-0.5 text-xs leading-6 text-slate-600">危害：{k.harm}</p> : null}
                {k.suggestion ? (
                  <p className="mt-0.5 text-xs leading-6 text-slate-600">整改建议：{k.suggestion}</p>
                ) : null}
              </div>
            ))}
          </div>
        ) : (
          <EmptyState title="未检索到相似漏洞" description="漏洞库中暂无与该内容相似的知识条目" />
        )}
      </Modal>

      {/* AI 总结 */}
      <Modal
        open={summaryText !== null}
        onClose={() => setSummaryText(null)}
        title="AI 总结"
        footer={
          <Button variant="primary" onClick={() => setSummaryText(null)}>
            关闭
          </Button>
        }
      >
        <p className="whitespace-pre-wrap text-[14px] leading-7 text-slate-700">{summaryText}</p>
      </Modal>
    </div>
  )
}
