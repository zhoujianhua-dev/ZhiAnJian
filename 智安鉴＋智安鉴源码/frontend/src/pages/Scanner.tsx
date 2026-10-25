import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Copy,
  Download,
  FilePlus2,
  Link2,
  Play,
  Radar,
  RefreshCw,
  ScrollText,
  Sparkles,
  Square,
} from 'lucide-react'
import { Card, CardBody, CardHeader, PageIntro } from '@/components/ui/card'
import { Badge, SeverityBadge, type BadgeTone } from '@/components/ui/badge'
import { Button, LinkButton } from '@/components/ui/button'
import { Field, Input } from '@/components/ui/field'
import { Modal } from '@/components/ui/modal'
import { DataTable, type Column } from '@/components/ui/table'
import { EmptyState, ErrorBlock, LoadingBlock, Pagination } from '@/components/ui/states'
import { SuggestInput } from '@/components/ui/suggest-input'
import { AddToReportsDialog } from '@/components/scanner/AddToReportsDialog'
import { useConfirm } from '@/components/ui/confirm'
import { useToast } from '@/components/ui/toast'
import { api } from '@/lib/api'
import { SEVERITY_STYLE, fmtTimeUtc8, severityOf } from '@/lib/format'
import { useQuery } from '@/lib/use-query'
import { cn } from '@/lib/cn'

/* ==================== 接口数据结构（与后端 snake_case 一致） ==================== */
interface StartData {
  scan_id: string
  target: string
  scan_type: string
  scan_type_cn: string
  status: string
  status_cn: string
  unit_name?: string
  system_name?: string
}

interface SubAgent {
  name: string
  role: string
  status: string
  progress: number
  findings_count: number
  summary: string
}

interface ProgressData {
  scan_id: string
  status: string
  status_cn: string
  phase: string
  message: string
  finished: boolean
  ok: boolean
  sub_agents: SubAgent[]
}

interface LogEntry {
  timestamp: string
  type: string
  type_cn: string
  message: string
  details: string
  tool: string
  agent: string
}

interface LogsData {
  scan_id: string
  logs: LogEntry[]
  next_index: number
  count: number
}

interface FindingData {
  title?: string
  severity?: string
  url?: string
  evidence?: string
  description?: string
}

interface Finding {
  source?: string
  data?: FindingData
}

interface ScanResultData {
  scan_id: string
  target: string
  scan_type_cn: string
  status: string
  status_cn: string
  llm_summary: string
  llm_risk_score: number | null
  unit_name?: string
  system_name?: string
  count: number
  severity_stats_cn: Record<string, number>
  findings: Finding[]
}

interface ScanItem {
  scan_id: string
  target: string
  scan_type: string
  scan_type_cn: string
  status: string
  status_cn: string
  created_at: string
  vulnerability_count: number
  llm_risk_score: number | null
  remark: string
  unit_name?: string
  system_name?: string
}

interface ScanListData {
  total: number
  items: ScanItem[]
  page: number
  page_size: number
}

interface AttackStep {
  order: number
  action: string
  vulnerability: string
  result: string
}

interface AttackChain {
  id: string
  name: string
  description: string
  likelihood: string
  likelihood_cn: string
  impact: string
  impact_cn: string
  steps: AttackStep[]
}

interface PhaseItem {
  id: string
  name: string
  severity: string
  details: string
}

interface AttackPhase {
  id: string
  name: string
  description: string
  items: PhaseItem[]
}

interface RiskAssessment {
  overall_risk: string
  overall_risk_cn: string
  risk_score: number | null
  summary: string
  critical_paths: string[]
  recommendations: string[]
}

interface AttackPathData {
  scan_id: string
  cached: boolean
  has_chains: boolean
  phases: AttackPhase[]
  attack_chains: AttackChain[]
  risk_assessment?: RiskAssessment
}

const EMPTY_RISK: RiskAssessment = {
  overall_risk: '',
  overall_risk_cn: '',
  risk_score: null,
  summary: '',
  critical_paths: [],
  recommendations: [],
}

/* ==================== 常量（沿用旧模板） ==================== */
const LIMIT = 10
/** 扫描进度轮询间隔（旧模板 2500ms） */
const STATUS_INTERVAL = 2500
/** 过程日志轮询间隔（旧模板 2000ms） */
const LOG_INTERVAL = 2000

const STATUS_TONE: Record<string, BadgeTone> = {
  COMPLETED: 'green',
  FAILED: 'red',
  RUNNING: 'blue',
  PENDING: 'blue',
}

function statusTone(status: string): BadgeTone {
  return STATUS_TONE[status] || 'slate'
}

/** 过程日志配色：info / tool / output / llm / error / success */
const LOG_STYLE: Record<string, string> = {
  info: 'border-sky-200 bg-sky-50 text-sky-700',
  tool: 'border-violet-200 bg-violet-50 text-violet-700',
  output: 'border-slate-200 bg-slate-50 text-slate-600',
  llm: 'border-amber-200 bg-amber-50 text-amber-700',
  error: 'border-red-200 bg-red-50 text-red-700',
  success: 'border-green-200 bg-green-50 text-green-700',
}

function logStyle(type: string) {
  return LOG_STYLE[type] || LOG_STYLE.info
}

/** 引擎/AI 输出字段统一转成可渲染文本，避免非字符串内容导致白屏 */
function asText(v: unknown): string {
  if (v === null || v === undefined) return ''
  if (typeof v === 'string') return v
  if (typeof v === 'number' || typeof v === 'boolean') return String(v)
  try {
    return JSON.stringify(v)
  } catch {
    return String(v)
  }
}

/** 引擎时间是 UTC ISO，日志里只显示北京时间的时分秒 */
function logTime(ts?: string | null) {
  if (!ts) return ''
  const full = fmtTimeUtc8(ts)
  if (!full || full === '-') return ''
  const hms = full.slice(11, 19)
  return hms || full
}

/** 攻击链等级徽章：颜色按 raw 等级，文案用后端给的中文（与旧页面一致） */
function LevelBadge({ level, text }: { level?: string; text?: string }) {
  const key = severityOf(level)
  return (
    <span
      className={cn(
        'inline-flex items-center whitespace-nowrap rounded border px-1.5 py-px text-[11.5px] font-medium leading-5',
        SEVERITY_STYLE[key],
      )}
    >
      {text || level || '-'}
    </span>
  )
}

export function Scanner() {
  const toast = useToast()
  const confirm = useConfirm()
  const navigate = useNavigate()

  /* ---------- 发起扫描 ---------- */
  const [target, setTarget] = useState('')
  const [unitName, setUnitName] = useState('')
  const [systemName, setSystemName] = useState('')
  const [remark, setRemark] = useState('')
  const [runState, setRunState] = useState<'idle' | 'submitting' | 'running'>('idle')
  const [startLabel, setStartLabel] = useState('开始扫描')

  /* ---------- 加入报告管理 ---------- */
  const [addTarget, setAddTarget] = useState<{
    scanId: string
    target: string
    unit: string
    system: string
    findings?: Finding[]
  } | null>(null)

  /* ---------- 扫描进度 ---------- */
  const [progress, setProgress] = useState<ProgressData | null>(null)
  const [progressError, setProgressError] = useState('')
  const [activeScanId, setActiveScanId] = useState('')
  const [resultLoading, setResultLoading] = useState(false)

  /* ---------- 扫描结果 ---------- */
  const [lastResult, setLastResult] = useState<ScanResultData | null>(null)
  const [cardVisible, setCardVisible] = useState(false)
  const [resultFor, setResultFor] = useState('')
  const [resultModalData, setResultModalData] = useState<ScanResultData | null>(null)
  const [resultModalLoading, setResultModalLoading] = useState(false)
  const [resultModalError, setResultModalError] = useState('')

  /* ---------- 过程日志 ---------- */
  const [logsFor, setLogsFor] = useState('')
  const [logEntries, setLogEntries] = useState<LogEntry[]>([])
  const [logStatus, setLogStatus] = useState('')
  const [logError, setLogError] = useState('')
  const [logLoading, setLogLoading] = useState(false)
  const [logStopped, setLogStopped] = useState(false)
  const [logFollow, setLogFollow] = useState(true)
  const logFollowRef = useRef(true)
  const logBoxRef = useRef<HTMLDivElement>(null)

  /* ---------- 攻击链分析 ---------- */
  const [attackFor, setAttackFor] = useState('')
  const [attackData, setAttackData] = useState<AttackPathData | null>(null)
  const [attackLoading, setAttackLoading] = useState(false)
  const [attackRefreshing, setAttackRefreshing] = useState(false)
  const [attackError, setAttackError] = useState('')
  const [attackStatus, setAttackStatus] = useState('')
  const attackSeq = useRef(0)

  /* ---------- 最近扫描列表 ---------- */
  const [page, setPage] = useState(1)
  const [refreshTick, setRefreshTick] = useState(0)
  const [editRemark, setEditRemark] = useState<{ scanId: string; original: string } | null>(null)
  /** scan_id → target，供「扫描过程 / 攻击链 / 扫描结果」弹窗显示标题 */
  const targetsRef = useRef<Map<string, string>>(new Map())
  const statusTimer = useRef<number | null>(null)
  const statusBusy = useRef(false)

  const load = useCallback(async () => {
    const res = await api.get<ScanListData>('/api/scanner/shelling/scans', {
      page,
      page_size: LIMIT,
    })
    const items = res.data?.items || []
    items.forEach((it) => targetsRef.current.set(it.scan_id, it.target || ''))
    return { rows: items, total: res.data?.total || 0 }
  }, [page, refreshTick])

  const { data, loading, error, reload, setData } = useQuery(load, [load])

  const dataRef = useRef(data)
  dataRef.current = data

  const engineDown = Boolean(error)
  const engineText = error
    ? '⚠ 扫描引擎不可达'
    : data
      ? '✔ 扫描引擎已连接'
      : '正在检测扫描引擎…'

  function titleOf(scanId: string) {
    return targetsRef.current.get(scanId) || scanId
  }

  /* ==================== 定时器清理（卸载必须清理） ==================== */
  const stopStatusPolling = useCallback(() => {
    if (statusTimer.current !== null) {
      window.clearInterval(statusTimer.current)
      statusTimer.current = null
    }
  }, [])

  useEffect(() => stopStatusPolling, [stopStatusPolling])

  /* ==================== 结果采纳（供复制 / 导出 / 带到报告） ==================== */
  function adoptResult(d: ScanResultData) {
    setLastResult(d)
    if (d.scan_id) {
      targetsRef.current.set(d.scan_id, d.target || targetsRef.current.get(d.scan_id) || '')
      setActiveScanId((cur) => cur || d.scan_id)
    }
  }

  /* ==================== 获取扫描结果 ==================== */
  const fetchResult = useCallback(
    async (scanId: string) => {
      setResultLoading(true)
      try {
        const res = await api.get<ScanResultData>(
          `/api/scanner/shelling/result/${encodeURIComponent(scanId)}`,
        )
        const d = res.data
        if (!d) {
          toast.error('获取结果失败：未知错误')
          return
        }
        adoptResult(d)
        setCardVisible(true)
        toast.success(`扫描完成，获取 ${d.count} 条漏洞数据`)
      } catch (e) {
        toast.error(`获取结果失败：${e instanceof Error ? e.message : '未知错误'}`)
      } finally {
        setResultLoading(false)
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [toast],
  )

  /* ==================== 进度轮询 ==================== */
  const finishScan = useCallback(
    async (scanId: string, p: ProgressData) => {
      if (!p.ok) {
        setRunState('idle')
        setStartLabel('重新扫描')
        toast.error(`扫描未成功完成：${p.status_cn || p.status || ''}`)
        return
      }
      await fetchResult(scanId)
      setRunState('idle')
      setStartLabel('再次扫描')
      setPage(1)
      setRefreshTick((n) => n + 1)
    },
    [fetchResult, toast],
  )

  const pollScan = useCallback(
    (scanId: string) => {
      stopStatusPolling()
      const tick = async () => {
        if (statusBusy.current) return
        statusBusy.current = true
        try {
          const res = await api.get<ProgressData>(
            `/api/scanner/shelling/status/${encodeURIComponent(scanId)}`,
          )
          const p = res.data
          if (!p) {
            setProgressError('查询进度失败')
            return
          }
          setProgress(p)
          setProgressError('')
          if (p.finished) {
            stopStatusPolling()
            await finishScan(scanId, p)
          }
        } catch (e) {
          setProgressError(`进度查询失败：${e instanceof Error ? e.message : '未知错误'}`)
        } finally {
          statusBusy.current = false
        }
      }
      statusTimer.current = window.setInterval(() => {
        void tick()
      }, STATUS_INTERVAL)
      void tick()
    },
    [finishScan, stopStatusPolling],
  )

  /* ==================== 发起扫描 ==================== */
  async function startScan() {
    const t = target.trim()
    if (!t) {
      toast.error('请填写扫描目标（域名 / IP / URL）')
      return
    }
    setRunState('submitting')
    setProgress(null)
    setProgressError('')
    try {
      const res = await api.post<StartData>('/api/scanner/shelling/start', {
        target: t,
        // 只提供全量扫描，不再暴露扫描类型选择
        scan_type: 'full',
        // 归属单位/系统随任务一起记录，后续「加入报告管理」直接回填
        unit_name: unitName.trim(),
        system_name: systemName.trim(),
        remark: remark.trim() || '智安鉴发起',
      })
      const d = res.data
      if (!d || !d.scan_id) {
        setProgressError(`提交失败：${res.msg || '未知错误'}`)
        setRunState('idle')
        setStartLabel('开始扫描')
        return
      }
      targetsRef.current.set(d.scan_id, d.target || t)
      setActiveScanId(d.scan_id)
      setRunState('running')
      pollScan(d.scan_id)
    } catch (e) {
      setProgressError(`提交失败：${e instanceof Error ? e.message : '未知错误'}`)
      setRunState('idle')
      setStartLabel('开始扫描')
    }
  }

  /* ==================== 取消扫描 ==================== */
  async function cancelScan() {
    if (!activeScanId) return
    const ok = await confirm({
      title: '取消扫描',
      message: '确定取消正在进行的扫描？',
      confirmText: '取消扫描',
    })
    if (!ok) return
    try {
      const res = await api.post(`/api/scanner/shelling/cancel/${encodeURIComponent(activeScanId)}`)
      toast.info(res.msg || '已请求取消扫描')
    } catch (e) {
      toast.error(`取消失败：${e instanceof Error ? e.message : '未知错误'}`)
    }
  }

  /* ==================== 复制 / 导出 / 带到 AI 生成报告 ==================== */
  function copyResult() {
    if (!lastResult) {
      toast.error('还没有可用的扫描结果')
      return
    }
    const text = JSON.stringify(lastResult.findings, null, 2)
    const fallback = () => {
      const ta = document.createElement('textarea')
      ta.value = text
      document.body.appendChild(ta)
      ta.select()
      try {
        document.execCommand('copy')
        toast.success('已复制到剪贴板')
      } catch {
        toast.error('复制失败，请手动选择文本')
      }
      document.body.removeChild(ta)
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard
        .writeText(text)
        .then(() => toast.success(`已复制 ${lastResult.findings.length} 条漏洞数据`))
        .catch(fallback)
    } else {
      fallback()
    }
  }

  function downloadResult() {
    if (!lastResult) {
      toast.error('还没有可用的扫描结果')
      return
    }
    const safe = String(lastResult.target || 'target').replace(/[^\w.\-]/g, '_')
    const name = `scan_${safe}_${String(lastResult.scan_id || '').slice(0, 8)}.json`
    const blob = new Blob([JSON.stringify(lastResult.findings, null, 2)], {
      type: 'application/json',
    })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = name
    a.click()
    window.setTimeout(() => URL.revokeObjectURL(a.href), 3000)
  }

  function sendToReportAi() {
    if (!lastResult) {
      toast.error('还没有可用的扫描结果')
      return
    }
    try {
      sessionStorage.setItem(
        'zhianjian_scan_handoff',
        JSON.stringify({
          scan_id: lastResult.scan_id || '',
          target: lastResult.target || '',
          findings: lastResult.findings || [],
          severity_stats_cn: lastResult.severity_stats_cn || {},
          llm_summary: lastResult.llm_summary || '',
          ts: Date.now(),
        }),
      )
    } catch (e) {
      toast.error(`无法暂存扫描结果：${e instanceof Error ? e.message : '未知错误'}`)
      return
    }
    toast.success('已带入 AI 智能生成页，正在跳转...')
    window.setTimeout(() => navigate('/reports/ai'), 400)
  }

  /* ==================== 扫描结果弹窗 ==================== */
  async function openScanResult(scanId: string) {
    if (!scanId) {
      toast.error('请先选择一次扫描任务')
      return
    }
    setResultFor(scanId)
    setResultModalData(null)
    setResultModalError('')
    setResultModalLoading(true)
    try {
      const res = await api.get<ScanResultData>(
        `/api/scanner/shelling/result/${encodeURIComponent(scanId)}`,
      )
      const d = res.data
      if (!d) {
        setResultModalError('读取失败：未知错误')
        return
      }
      adoptResult(d)
      setResultModalData(d)
    } catch (e) {
      setResultModalError(`读取失败：${e instanceof Error ? e.message : '未知错误'}`)
    } finally {
      setResultModalLoading(false)
    }
  }

  /* ==================== 过程日志 ==================== */
  function openLogs(scanId: string) {
    if (!scanId) {
      toast.error('请先选择一次扫描任务')
      return
    }
    setLogEntries([])
    setLogStatus('')
    setLogError('')
    setLogStopped(false)
    setLogLoading(true)
    logFollowRef.current = true
    setLogFollow(true)
    setLogsFor(scanId)
  }

  function toggleFollow() {
    const next = !logFollowRef.current
    logFollowRef.current = next
    setLogFollow(next)
  }

  // 日志增量拉取（since_index 续拉）；关闭弹窗 / 卸载时清理定时器
  useEffect(() => {
    if (!logsFor) return
    let cancelled = false
    let stopped = false
    let next = 0
    let idle = 0
    let total = 0
    let busy = false
    let timer: number | null = null

    const clearTimer = () => {
      if (timer !== null) {
        window.clearInterval(timer)
        timer = null
      }
    }

    const poll = async () => {
      if (cancelled || stopped || busy) return
      busy = true
      try {
        const res = await api.get<LogsData>(
          `/api/scanner/shelling/logs/${encodeURIComponent(logsFor)}`,
          { since_index: next },
        )
        if (cancelled) return
        const d = res.data
        const logs = d?.logs || []
        if (d && typeof d.next_index === 'number') next = d.next_index
        if (logs.length) {
          setLogEntries((prev) => [...prev, ...logs])
          total += logs.length
          idle = 0
        } else {
          idle += 1
        }
        /* 连续两次没有新日志：复核任务状态，已结束就停止轮询 */
        if (idle >= 2) {
          let finished = false
          try {
            const st = await api.get<ProgressData>(
              `/api/scanner/shelling/status/${encodeURIComponent(logsFor)}`,
            )
            finished = Boolean(st.data?.finished)
          } catch {
            /* 状态查询失败则继续轮询 */
          }
          if (cancelled) return
          if (finished) {
            stopped = true
            clearTimer()
            setLogStopped(true)
            setLogStatus(total > 0 ? `扫描已结束，共 ${total} 条日志` : '扫描已结束')
            return
          }
          idle = 0
        }
      } catch (e) {
        if (cancelled) return
        stopped = true
        clearTimer()
        setLogError(`读取日志失败：${e instanceof Error ? e.message : '未知错误'}`)
      } finally {
        busy = false
      }
    }

    void poll().finally(() => {
      if (cancelled) return
      setLogLoading(false)
      if (!stopped) {
        timer = window.setInterval(() => {
          void poll()
        }, LOG_INTERVAL)
      }
    })

    return () => {
      cancelled = true
      clearTimer()
    }
  }, [logsFor])

  // 跟随模式：新日志进来后自动滚到底部
  useEffect(() => {
    if (!logFollowRef.current) return
    const box = logBoxRef.current
    if (box) box.scrollTop = box.scrollHeight
  }, [logEntries])

  /* ==================== 攻击链分析 ==================== */
  async function loadAttackPath(scanId: string, refresh: boolean) {
    const seq = ++attackSeq.current
    setAttackLoading(true)
    setAttackRefreshing(refresh)
    setAttackError('')
    setAttackStatus(refresh ? 'AI 正在重新分析，请稍候…' : '')
    try {
      const res = await api.get<AttackPathData>(
        `/api/scanner/shelling/attack-path/${encodeURIComponent(scanId)}`,
        refresh ? { refresh: 'true' } : undefined,
      )
      if (seq !== attackSeq.current) return
      const d = res.data
      if (!d) {
        setAttackError('读取失败：未知错误')
        return
      }
      setAttackData(d)
      setAttackStatus(d.cached ? '结果来自缓存（点「重新分析」可强制刷新）' : '')
    } catch (e) {
      if (seq !== attackSeq.current) return
      setAttackError(`读取失败：${e instanceof Error ? e.message : '未知错误'}`)
    } finally {
      if (seq === attackSeq.current) {
        setAttackLoading(false)
        setAttackRefreshing(false)
      }
    }
  }

  function openAttackPath(scanId: string) {
    if (!scanId) {
      toast.error('请先选择一次扫描任务')
      return
    }
    setAttackFor(scanId)
    setAttackData(null)
    setAttackError('')
    void loadAttackPath(scanId, false)
  }

  /* ==================== 删除扫描任务（进行中的由后端先取消再删除） ==================== */
  async function removeScan(item: ScanItem) {
    const t = item.target || targetsRef.current.get(item.scan_id) || ''
    const running = item.status === 'RUNNING' || item.status === 'PENDING'
    const tip = running ? '该扫描仍在进行中，删除前会先取消它。' : '该任务的扫描结果与过程记录会一并删除。'
    const ok = await confirm({
      message: (
        <span>
          确定删除扫描任务{t ? `（${t}）` : ''}？
          <br />
          <span className="text-slate-500">{tip}删除后不可恢复。</span>
        </span>
      ),
      confirmText: '删除',
    })
    if (!ok) return
    try {
      const res = await api.post(`/api/scanner/shelling/delete/${encodeURIComponent(item.scan_id)}`)
      targetsRef.current.delete(item.scan_id)
      toast.success(res.msg || '已删除')
      /* 正在查看的扫描被删除时，收起结果卡片并停止轮询，避免残留 */
      if (item.scan_id === activeScanId) {
        setActiveScanId('')
        setCardVisible(false)
        setLastResult(null)
        setProgress(null)
        setProgressError('')
        stopStatusPolling()
        setRunState('idle')
        setStartLabel('开始扫描')
      }
      if (data && data.rows.length === 1 && page > 1) setPage(page - 1)
      else setRefreshTick((n) => n + 1)
    } catch (e) {
      toast.error(`删除失败：${e instanceof Error ? e.message : '未知错误'}`)
    }
  }

  /* ==================== 备注双击编辑 ==================== */
  function patchRemark(scanId: string, remark: string) {
    const cur = dataRef.current
    if (!cur) return
    setData({
      ...cur,
      rows: cur.rows.map((r) => (r.scan_id === scanId ? { ...r, remark } : r)),
    })
  }

  async function commitRemark(item: ScanItem, value: string | null) {
    const original = item.remark || ''
    setEditRemark(null)
    if (value === null || value === original) return
    patchRemark(item.scan_id, value) /* 先乐观更新，失败再回滚 */
    try {
      const res = await api.post<{ scan_id: string; remark: string }>(
        `/api/scanner/shelling/remark/${encodeURIComponent(item.scan_id)}`,
        { remark: value },
      )
      patchRemark(item.scan_id, res.data?.remark ?? value)
      toast.success(res.msg || '备注已更新')
    } catch (e) {
      patchRemark(item.scan_id, original)
      toast.error(`备注保存失败：${e instanceof Error ? e.message : '未知错误'}`)
    }
  }

  /* ==================== 最近扫描表格 ==================== */
  const columns: Column<ScanItem>[] = [
    {
      key: 'created_at',
      title: '发起时间',
      width: 150,
      render: (it) => (
        <span className="whitespace-nowrap text-xs text-slate-500">{fmtTimeUtc8(it.created_at)}</span>
      ),
    },
    {
      key: 'target',
      title: '目标',
      render: (it) => (
        <div className="min-w-0">
          <span className="block break-all font-medium text-slate-800">{it.target}</span>
          {it.unit_name || it.system_name ? (
            <span className="mt-0.5 block break-words text-xs text-slate-500">
              {it.unit_name || '未填单位'}
              {it.system_name ? ` · ${it.system_name}` : ''}
            </span>
          ) : null}
        </div>
      ),
    },
    {
      key: 'scan_type',
      title: '类型',
      width: 100,
      render: (it) => <span className="text-slate-600">{it.scan_type_cn || '-'}</span>,
    },
    {
      key: 'status',
      title: '状态',
      width: 90,
      render: (it) => <Badge tone={statusTone(it.status)}>{it.status_cn || it.status}</Badge>,
    },
    {
      key: 'vulnerability_count',
      title: '漏洞数',
      width: 76,
      align: 'center',
      render: (it) => <span className="tnum text-slate-700">{it.vulnerability_count}</span>,
    },
    {
      key: 'llm_risk_score',
      title: '风险评分',
      width: 84,
      align: 'center',
      render: (it) => (
        <span className="tnum text-slate-700">
          {it.llm_risk_score === null || it.llm_risk_score === undefined ? '-' : it.llm_risk_score}
        </span>
      ),
    },
    {
      key: 'remark',
      title: '备注',
      width: 180,
      render: (it) =>
        editRemark && editRemark.scanId === it.scan_id ? (
          <RemarkInput
            initial={editRemark.original}
            onDone={(v) => {
              void commitRemark(it, v)
            }}
          />
        ) : (
          <span
            title="双击编辑备注"
            className="block max-w-[200px] cursor-text break-words text-xs text-slate-500"
            onDoubleClick={() => setEditRemark({ scanId: it.scan_id, original: it.remark || '' })}
          >
            {it.remark ? it.remark : <span className="text-slate-300">—</span>}
          </span>
        ),
    },
    {
      key: 'actions',
      title: '操作',
      width: 240,
      render: (it) => (
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <LinkButton onClick={() => void openScanResult(it.scan_id)}>查看结果</LinkButton>
          <span className="text-slate-300">·</span>
          <LinkButton onClick={() => openLogs(it.scan_id)}>扫描过程</LinkButton>
          <span className="text-slate-300">·</span>
          <LinkButton onClick={() => openAttackPath(it.scan_id)}>攻击链</LinkButton>
          <span className="text-slate-300">·</span>
          {it.status === 'COMPLETED' && it.vulnerability_count > 0 ? (
            <>
              <LinkButton
                onClick={() =>
                  setAddTarget({
                    scanId: it.scan_id,
                    target: it.target,
                    unit: it.unit_name || '',
                    system: it.system_name || '',
                  })
                }
              >
                加入报告
              </LinkButton>
              <span className="text-slate-300">·</span>
            </>
          ) : null}
          <LinkButton danger onClick={() => void removeScan(it)}>
            删除
          </LinkButton>
        </div>
      ),
    },
  ]

  const submitting = runState === 'submitting'
  const running = runState === 'running'
  const startBtnText = submitting ? '提交中...' : running ? '扫描进行中...' : startLabel

  return (
    <div className="flex flex-col gap-4">
      <PageIntro
        icon={<Radar size={17} />}
        title="扫描引擎"
        description="扫描引擎已内置在系统中、无需任何配置：发起扫描 → 实时查看子 Agent 进度 → 回收漏洞结果 → 一键加入报告管理或带到「AI 智能生成报告」"
        actions={
          <span className={cn('text-xs', engineDown ? 'text-red-600' : data ? 'text-emerald-600' : 'text-slate-400')}>
            {engineText}
          </span>
        }
      />

      <div className="grid gap-4 lg:grid-cols-2">
        {/* ① 发起扫描 */}
        <Card>
          <CardHeader title="① 发起扫描" description="目标支持域名 / IP / URL" />
          <CardBody>
            <div className="grid gap-3.5 sm:grid-cols-2">
              <Field label="扫描目标" className="sm:col-span-2">
                <Input
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') void startScan()
                  }}
                  disabled={submitting || running}
                  placeholder="10.0.5.145 或 https://example.com"
                />
              </Field>
              <Field label="所属单位名称" hint="可选，加入报告管理时自动带入">
                <SuggestInput
                  value={unitName}
                  onChange={setUnitName}
                  disabled={submitting || running}
                  placeholder="如：XX 网络科技有限公司"
                  load={async (kw) => {
                    const res = await api.get<Array<{ id: number; enterprise_name: string }>>(
                      '/api/unit/search',
                      { q: kw },
                    )
                    return (res.data || []).map((u) => u.enterprise_name).filter(Boolean)
                  }}
                />
              </Field>
              <Field label="系统名称" hint="可选，留空则报告里不填系统">
                <Input
                  value={systemName}
                  onChange={(e) => setSystemName(e.target.value)}
                  disabled={submitting || running}
                  placeholder="如：官网 / 后台管理系统"
                />
              </Field>
              <Field label="备注（可选）" className="sm:col-span-2">
                <Input
                  value={remark}
                  onChange={(e) => setRemark(e.target.value)}
                  placeholder="智安鉴发起"
                />
              </Field>
            </div>

            <div className="mt-3 flex flex-wrap items-center gap-2">
              <Button
                variant="primary"
                icon={<Play size={14} />}
                loading={submitting}
                disabled={running}
                onClick={() => void startScan()}
              >
                {startBtnText}
              </Button>
              {running ? (
                <Button variant="ghost" icon={<Square size={13} />} onClick={() => void cancelScan()}>
                  取消扫描
                </Button>
              ) : null}
            </div>

            <p className="mt-2.5 text-xs leading-5 text-slate-500">
              扫描由扫描引擎的多子 Agent 编排执行（资产探测 → 漏洞验证 → AI 校验 → 汇总），
              结果会自动转换为智安鉴统一的漏洞数据结构，可直接进入报告生成流程。
              <br />
              提示：请仅对已获得授权的目标发起扫描。
            </p>
          </CardBody>
        </Card>

        {/* ② 扫描进度 */}
        <Card>
          <CardHeader
            title="② 扫描进度"
            actions={
              <>
                {progress?.phase ? (
                  <span className="text-xs text-slate-400">阶段：{progress.phase}</span>
                ) : null}
                {activeScanId ? (
                  <Button
                    variant="ghost"
                    size="sm"
                    icon={<ScrollText size={13} />}
                    onClick={() => openLogs(activeScanId)}
                  >
                    查看过程
                  </Button>
                ) : null}
              </>
            }
          />
          <CardBody>
            {progressError ? (
              <p className="text-[13px] text-red-600">{progressError}</p>
            ) : submitting ? (
              <div className="flex items-center gap-2 text-[13px] text-primary">
                <RefreshCw size={14} className="animate-spin" />
                正在提交扫描任务...
              </div>
            ) : progress ? (
              <div className="rounded-md border border-primary-line bg-primary-soft px-3.5 py-2.5">
                <div className="flex items-start justify-between gap-2.5">
                  <b className="text-[13px] text-slate-800">
                    {progress.status_cn || progress.status || ''}
                  </b>
                  <span className="shrink-0 text-xs text-slate-500">{progress.scan_id}</span>
                </div>
                {progress.message ? (
                  <p className="mt-0.5 text-xs leading-5 text-slate-600">{progress.message}</p>
                ) : null}
                {(progress.sub_agents || []).map((s, i) => {
                  const pct = Math.max(0, Math.min(100, Number(s.progress) || 0))
                  return (
                    <div key={`${s.name}-${i}`} className="mt-2">
                      <div className="flex items-start justify-between gap-2 text-xs text-slate-600">
                        <span className="min-w-0 break-words">
                          <b className="text-slate-800">{asText(s.name)}</b>{' '}
                          <span className="text-slate-400">{asText(s.role)}</span>
                        </span>
                        <span className="shrink-0 whitespace-nowrap">
                          {asText(s.status)}
                          {s.findings_count ? ` · 发现 ${s.findings_count}` : ''}
                        </span>
                      </div>
                      <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-slate-200">
                        <div
                          className="h-full bg-primary transition-[width] duration-300"
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                      {s.summary ? (
                        <p className="mt-1 break-words text-[11.5px] leading-5 text-slate-500">
                          {asText(s.summary)}
                        </p>
                      ) : null}
                    </div>
                  )
                })}
                {resultLoading ? (
                  <p className="mt-2 text-[13px] text-primary">扫描完成，正在获取漏洞结果...</p>
                ) : null}
              </div>
            ) : (
              <EmptyState
                title="尚未发起扫描"
                description="填写左侧目标后点「开始扫描」，这里会显示实时进度"
              />
            )}
          </CardBody>
        </Card>
      </div>

      {/* ③ 扫描结果 */}
      {cardVisible && lastResult ? (
        <Card>
          <CardHeader
            title="③ 扫描结果"
            actions={
              <>
                <Button
                  variant="primary"
                  size="sm"
                  icon={<FilePlus2 size={13} />}
                  onClick={() =>
                    setAddTarget({
                      scanId: lastResult.scan_id,
                      target: lastResult.target,
                      unit: lastResult.unit_name || unitName,
                      system: lastResult.system_name || systemName,
                      findings: lastResult.findings,
                    })
                  }
                >
                  加入报告管理
                </Button>
                <Button
                  variant="secondary"
                  size="sm"
                  icon={<Sparkles size={13} />}
                  onClick={sendToReportAi}
                >
                  带到 AI 生成报告
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  icon={<Link2 size={13} />}
                  onClick={() => openAttackPath(lastResult.scan_id)}
                >
                  攻击链
                </Button>
                <Button variant="ghost" size="sm" icon={<Copy size={13} />} onClick={copyResult}>
                  复制 JSON
                </Button>
                <Button variant="ghost" size="sm" icon={<Download size={13} />} onClick={downloadResult}>
                  导出 JSON
                </Button>
              </>
            }
          />
          <CardBody>
            <ResultSummary data={lastResult} />
            <div className="mt-3">
              <FindingsTable findings={lastResult.findings} />
            </div>
          </CardBody>
        </Card>
      ) : null}

      {/* 最近扫描 */}
      <Card>
        <CardHeader
          title="最近扫描"
          actions={
            <Button
              variant="ghost"
              size="sm"
              icon={<RefreshCw size={13} />}
              onClick={() => setRefreshTick((n) => n + 1)}
            >
              刷新
            </Button>
          }
        />
        {error ? (
          <ErrorBlock message={`读取失败：${error}`} onRetry={() => void reload()} />
        ) : (
          <DataTable
            columns={columns}
            rows={data?.rows || []}
            rowKey={(it) => it.scan_id}
            loading={loading}
            empty={
              <EmptyState
                title="暂无扫描记录"
                description="发起一次扫描后，这里会列出历史任务与结果入口"
              />
            }
          />
        )}
        <div className="border-t border-line px-4 py-3">
          <Pagination page={page} total={data?.total || 0} limit={LIMIT} onChange={setPage} />
        </div>
      </Card>

      {/* 加入报告管理 */}
      <AddToReportsDialog
        open={Boolean(addTarget)}
        onClose={() => setAddTarget(null)}
        scanId={addTarget?.scanId || ''}
        target={addTarget?.target || ''}
        findings={addTarget?.findings}
        defaultUnit={addTarget?.unit}
        defaultSystem={addTarget?.system}
        onAdded={() => setRefreshTick((n) => n + 1)}
      />

      {/* 扫描结果弹窗 */}
      <Modal
        open={Boolean(resultFor)}
        onClose={() => setResultFor('')}
        title={`扫描结果 · ${resultFor ? titleOf(resultFor) : ''}`}
        size="xl"
        footer={
          <>
            <Button variant="ghost" icon={<Copy size={13} />} onClick={copyResult}>
              复制 JSON
            </Button>
            <Button variant="ghost" icon={<Download size={13} />} onClick={downloadResult}>
              导出 JSON
            </Button>
            <Button
              variant="primary"
              icon={<FilePlus2 size={13} />}
              disabled={!resultModalData?.findings?.length}
              onClick={() =>
                resultModalData &&
                setAddTarget({
                  scanId: resultModalData.scan_id,
                  target: resultModalData.target,
                  unit: resultModalData.unit_name || unitName,
                  system: resultModalData.system_name || systemName,
                  findings: resultModalData.findings,
                })
              }
            >
              加入报告管理
            </Button>
            <Button variant="secondary" icon={<Sparkles size={13} />} onClick={sendToReportAi}>
              带到 AI 生成报告
            </Button>
            <Button variant="ghost" onClick={() => setResultFor('')}>
              关闭
            </Button>
          </>
        }
      >
        {resultModalLoading ? (
          <LoadingBlock text="正在读取该次扫描的结果…" />
        ) : resultModalError ? (
          <p className="text-[13px] text-red-600">{resultModalError}</p>
        ) : resultModalData ? (
          <div>
            <ResultSummary data={resultModalData} />
            <div className="mt-3">
              <FindingsTable findings={resultModalData.findings} />
            </div>
          </div>
        ) : null}
      </Modal>

      {/* 扫描过程弹窗 */}
      <Modal
        open={Boolean(logsFor)}
        onClose={() => setLogsFor('')}
        title={`扫描过程 · ${logsFor ? titleOf(logsFor) : ''}`}
        size="xl"
        footer={
          <>
            <span className="mr-auto text-xs text-slate-500">
              {logLoading && logEntries.length === 0 ? '正在读取…' : logStatus}
            </span>
            <Button variant="ghost" onClick={toggleFollow}>
              {logFollow ? '暂停跟随' : '继续跟随'}
            </Button>
            <Button variant="primary" onClick={() => setLogsFor('')}>
              关闭
            </Button>
          </>
        }
      >
        <div className="mb-2.5 flex flex-wrap items-center justify-between gap-2.5">
          <span className="text-xs text-slate-500">
            扫描引擎各 Agent 的执行日志，扫描进行中会实时刷新
          </span>
          <span className="text-xs text-slate-400">共 {logEntries.length} 条</span>
        </div>
        {logError ? (
          <p className="text-[13px] text-red-600">{logError}</p>
        ) : logEntries.length === 0 ? (
          logStopped ? (
            <EmptyState title="暂无过程日志" description="该扫描任务没有产生过程日志" />
          ) : (
            <LoadingBlock text="正在读取…" />
          )
        ) : null}
        <div ref={logBoxRef} className={cn('max-h-[58vh] overflow-y-auto', logEntries.length === 0 && 'hidden')}>
          {logEntries.map((e, i) => (
            <div
              key={i}
              className={cn('mb-1.5 flex gap-2 rounded-md border px-2.5 py-1.5', logStyle(e.type))}
            >
              <div className="whitespace-nowrap pt-px text-[11px] text-slate-400">
                {logTime(e.timestamp)}
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="text-[11px] font-bold">{e.type_cn || e.type}</span>
                  {e.agent ? <Badge tone="slate" className="text-[10.5px]">{e.agent}</Badge> : null}
                  {e.tool ? <Badge tone="blue" className="text-[10.5px]">🔧 {e.tool}</Badge> : null}
                </div>
                <div className="mt-0.5 break-words text-[12.5px] text-slate-800">{asText(e.message)}</div>
                {e.details ? (
                  <div className="mt-0.5 whitespace-pre-wrap break-words text-[11.5px] text-slate-500">
                    {asText(e.details)}
                  </div>
                ) : null}
              </div>
            </div>
          ))}
        </div>
      </Modal>

      {/* 攻击链分析弹窗 */}
      <Modal
        open={Boolean(attackFor)}
        onClose={() => setAttackFor('')}
        title={`攻击链分析 · ${attackFor ? titleOf(attackFor) : ''}`}
        size="xl"
        footer={
          <>
            <span className="mr-auto text-xs text-slate-500">{attackStatus}</span>
            <Button
              variant="ghost"
              icon={<RefreshCw size={13} className={attackRefreshing ? 'animate-spin' : undefined} />}
              loading={attackRefreshing}
              onClick={() => {
                if (attackFor) void loadAttackPath(attackFor, true)
              }}
            >
              重新分析
            </Button>
            <Button variant="primary" onClick={() => setAttackFor('')}>
              关闭
            </Button>
          </>
        }
      >
        {attackLoading && (attackRefreshing || !attackData) ? (
          <LoadingBlock
            text={
              attackRefreshing
                ? '正在调用 AI 重新分析攻击链（约需 10~30 秒）…'
                : '正在读取攻击链分析…'
            }
          />
        ) : attackError ? (
          <p className="py-3 text-[13px] text-red-600">{attackError}</p>
        ) : attackData ? (
          <AttackPathView data={attackData} />
        ) : null}
      </Modal>
    </div>
  )
}

/* ==================== 备注行内编辑 ==================== */
function RemarkInput({
  initial,
  onDone,
}: {
  initial: string
  onDone: (value: string | null) => void
}) {
  const [value, setValue] = useState(initial)
  const done = useRef(false)

  const finish = (save: boolean) => {
    if (done.current) return
    done.current = true
    onDone(save ? value.trim() : null)
  }

  return (
    <Input
      autoFocus
      maxLength={200}
      value={value}
      className="h-[26px] px-1.5 text-xs"
      onChange={(e) => setValue(e.target.value)}
      onFocus={(e) => e.currentTarget.select()}
      onKeyDown={(e) => {
        if (e.key === 'Enter') {
          e.preventDefault()
          finish(true)
        } else if (e.key === 'Escape') {
          e.preventDefault()
          finish(false)
        }
      }}
      onBlur={() => finish(true)}
    />
  )
}

/* ==================== 结果摘要（卡片与弹窗共用） ==================== */
function ResultSummary({ data }: { data: ScanResultData }) {
  const stats = Object.entries(data.severity_stats_cn || {})
  return (
    <div className="text-[13px] leading-6">
      <div className="flex flex-wrap items-center gap-x-1.5 gap-y-1">
        <span>
          目标 <b className="text-slate-900">{data.target || '-'}</b>
        </span>
        <span className="text-slate-400">·</span>
        <span className="text-slate-600">{data.scan_type_cn || ''}</span>
        <span className="text-slate-400">·</span>
        <span className="text-slate-500">{data.status_cn || data.status || ''}</span>
        <span className="text-slate-400">·</span>
        <span>
          共 <b className="tnum text-slate-900">{data.count}</b> 条发现
        </span>
        {stats.map(([k, n]) => (
          <Badge key={k} tone="blue">
            {k} × {n}
          </Badge>
        ))}
        {data.llm_risk_score === null || data.llm_risk_score === undefined ? null : (
          <Badge tone="slate">风险评分 {data.llm_risk_score}</Badge>
        )}
      </div>
      {data.llm_summary ? (
        <p className="mt-1 break-words text-xs leading-5 text-violet-700">
          AI 摘要：{data.llm_summary}
        </p>
      ) : null}
    </div>
  )
}

/* ==================== 漏洞清单 ==================== */
function FindingsTable({ findings }: { findings: Finding[] }) {
  const columns: Column<Finding>[] = [
    {
      key: 'severity',
      title: '等级',
      width: 72,
      render: (f) => <SeverityBadge severity={f.data?.severity} />,
    },
    {
      key: 'title',
      title: '漏洞名称',
      width: '26%',
      render: (f) => (
        <span className="break-words font-semibold text-slate-800">{f.data?.title || '-'}</span>
      ),
    },
    {
      key: 'url',
      title: '位置',
      width: '22%',
      render: (f) => (
        <span className="break-all text-xs text-slate-600">{f.data?.url || '-'}</span>
      ),
    },
    {
      key: 'evidence',
      title: '证据 / 说明',
      render: (f) => {
        const evidence = String(f.data?.evidence || '').replace(/\n/g, ' / ')
        const desc = String(f.data?.description || '')
        return (
          <div className="max-w-[420px]">
            <div className="break-words text-xs text-slate-600">{evidence || '-'}</div>
            {desc ? (
              <div className="mt-0.5 truncate text-xs text-slate-400" title={desc}>
                {desc}
              </div>
            ) : null}
          </div>
        )
      },
    },
  ]

  return (
    <DataTable
      columns={columns}
      rows={findings || []}
      rowKey={(_, i) => i}
      empty={<div className="py-6 text-center text-[13px] text-slate-400">本次扫描没有发现漏洞</div>}
    />
  )
}

/* ==================== 攻击链分析内容 ==================== */
function AttackPathView({ data }: { data: AttackPathData }) {
  const risk = data.risk_assessment || EMPTY_RISK
  const chains = data.attack_chains || []
  const phases = data.phases || []
  const score = risk.risk_score === null || risk.risk_score === undefined ? '-' : risk.risk_score

  return (
    <div>
      {/* 1) 整体风险评估 */}
      <div className="rounded-md border border-line px-4 py-3.5">
        <div className="flex flex-wrap items-center gap-2.5">
          <span className="text-[13px] font-bold text-slate-700">整体风险</span>
          <LevelBadge level={risk.overall_risk} text={risk.overall_risk_cn || risk.overall_risk || '-'} />
          <Badge tone="slate">风险评分 {String(score)} / 100</Badge>
        </div>
        {risk.summary ? (
          <p className="mt-2 break-words text-[12.5px] leading-6 text-slate-600">{asText(risk.summary)}</p>
        ) : null}
        {risk.critical_paths && risk.critical_paths.length ? (
          <div className="mt-2.5">
            <div className="text-[12.5px] font-bold text-slate-700">关键路径</div>
            <ul className="mt-1 list-disc pl-5 text-[12.5px] leading-6 text-slate-600">
              {risk.critical_paths.map((x, i) => (
                <li key={i} className="break-words">
                  {asText(x)}
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        {risk.recommendations && risk.recommendations.length ? (
          <div className="mt-2.5">
            <div className="text-[12.5px] font-bold text-slate-700">处置建议</div>
            <ul className="mt-1 list-disc pl-5 text-[12.5px] leading-6 text-slate-600">
              {risk.recommendations.map((x, i) => (
                <li key={i} className="break-words">
                  {asText(x)}
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </div>

      {/* 2) 攻击链 */}
      {chains.length === 0 ? (
        <div className="mt-3.5 flex items-start gap-2.5 rounded-md border border-amber-200 bg-amber-50 px-3.5 py-3 text-amber-800">
          <span className="mt-0.5 shrink-0 text-amber-500">⚠</span>
          <div className="text-[12.5px] leading-6">
            <b>本次未生成可用的攻击链</b>
            <div className="mt-0.5">
              攻击链需要扫描引擎的 AI 输出完整结构。出现这种情况通常是因为：目标未发现可串联的有效漏洞
              （多为信息类或未验证风险），或 AI 分析输出不完整被判定为不可靠。
              可点右下角「重新分析」重试；若仍为空，说明该目标当前缺少可构建攻击链的有效漏洞。
            </div>
          </div>
        </div>
      ) : (
        <div className="mt-3.5">
          <div className="mb-2 text-[13px] font-bold text-slate-700">攻击链（{chains.length}）</div>
          {chains.map((c, idx) => (
            <div key={c.id || idx} className="mb-3 rounded-md border border-line px-4 py-3.5">
              <div className="flex flex-wrap items-center gap-2.5">
                <span className="text-[13px] font-bold text-slate-700">
                  {idx + 1}. {asText(c.name)}
                </span>
                <Badge tone="slate">可能性 {c.likelihood_cn || '-'}</Badge>
                <LevelBadge level={c.impact} text={`影响 ${c.impact_cn || '-'}`} />
              </div>
              {c.description ? (
                <p className="mt-1.5 break-words text-[12.5px] leading-6 text-slate-500">
                  {asText(c.description)}
                </p>
              ) : null}
              <div className="mt-2">
                {(c.steps || []).map((s, si) => (
                  <div
                    key={si}
                    className="flex gap-2.5 border-t border-dashed border-slate-100 py-2 first:border-t-0"
                  >
                    <div className="flex h-[22px] w-[22px] shrink-0 items-center justify-center rounded-full bg-primary-soft text-[11.5px] font-bold text-primary">
                      {s.order || 0}
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="break-words text-[12.5px] leading-6 text-slate-800">{asText(s.action)}</div>
                      {s.vulnerability ? (
                        <div className="mt-0.5 break-words text-[11.5px] text-violet-700">
                          关联漏洞：{asText(s.vulnerability)}
                        </div>
                      ) : null}
                      {s.result ? (
                        <div className="mt-0.5 break-words text-[11.5px] text-slate-500">
                          预期结果：{asText(s.result)}
                        </div>
                      ) : null}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* 3) 阶段分析 */}
      {phases.length ? (
        <div className="mt-4">
          <div className="mb-2 text-[13px] font-bold text-slate-700">阶段分析</div>
          {phases.map((p, pi) => (
            <div key={p.id || pi} className="mb-2.5 rounded-md border border-line px-4 py-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-[12.5px] font-bold text-slate-700">{asText(p.name)}</span>
                <Badge tone="slate">{(p.items || []).length} 项</Badge>
              </div>
              {p.description ? (
                <p className="mt-1 break-words text-xs leading-5 text-slate-500">{asText(p.description)}</p>
              ) : null}
              <div className="mt-1">
                {(p.items || []).length === 0 ? (
                  <div className="py-1.5 text-xs text-slate-400">该阶段无内容</div>
                ) : (
                  (p.items || []).map((i, ii) => (
                    <div
                      key={i.id || ii}
                      className="flex items-start gap-2 border-t border-dashed border-slate-100 py-1.5 first:border-t-0"
                    >
                      <SeverityBadge severity={i.severity} />
                      <div className="min-w-0 flex-1">
                        <div className="break-words text-[12.5px] font-semibold text-slate-800">
                          {asText(i.name)}
                        </div>
                        {i.details ? (
                          <div className="mt-0.5 break-words text-[11.5px] leading-5 text-slate-500">
                            {asText(i.details)}
                          </div>
                        ) : null}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          ))}
        </div>
      ) : null}
    </div>
  )
}
