/** 展示层格式化：等级 / 生命周期 / 时间 / 主机名提取（口径与后端一致） */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown'

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info', 'unknown']

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
  unknown: '未知',
}

/** 徽章配色（扁平：浅底 + 深字 + 同色描边） */
export const SEVERITY_STYLE: Record<Severity, string> = {
  critical: 'bg-red-50 text-red-700 border-red-200',
  high: 'bg-orange-50 text-orange-700 border-orange-200',
  medium: 'bg-amber-50 text-amber-700 border-amber-200',
  low: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  info: 'bg-sky-50 text-sky-700 border-sky-200',
  unknown: 'bg-slate-100 text-slate-600 border-slate-200',
}

export const SEVERITY_DOT: Record<Severity, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#d97706',
  low: '#059669',
  info: '#0284c7',
  unknown: '#94a3b8',
}

export function severityOf(v?: string | null): Severity {
  return (SEVERITY_ORDER as string[]).includes(v || '') ? (v as Severity) : 'unknown'
}

export function severityLabel(v?: string | null) {
  return SEVERITY_LABEL[severityOf(v)]
}

/** 漏洞处置生命周期：open → fixing → fixed → verified */
export type Lifecycle = 'open' | 'fixing' | 'fixed' | 'verified'

export const LIFECYCLE_ORDER: Lifecycle[] = ['open', 'fixing', 'fixed', 'verified']

export const LIFECYCLE_LABEL: Record<Lifecycle, string> = {
  open: '待整改',
  fixing: '整改中',
  fixed: '已修复待复测',
  verified: '复测通过',
}

export const LIFECYCLE_STYLE: Record<Lifecycle, string> = {
  open: 'bg-red-50 text-red-700 border-red-200',
  fixing: 'bg-blue-50 text-blue-700 border-blue-200',
  fixed: 'bg-amber-50 text-amber-700 border-amber-200',
  verified: 'bg-emerald-50 text-emerald-700 border-emerald-200',
}

export function lifecycleOf(v?: string | null): Lifecycle {
  return (LIFECYCLE_ORDER as string[]).includes(v || '') ? (v as Lifecycle) : 'open'
}

export function lifecycleLabel(v?: string | null) {
  return LIFECYCLE_LABEL[lifecycleOf(v)]
}

/** 后端时间已是本地展示格式（YYYY-MM-DD HH:MM:SS），截断到秒 */
export function fmtTime(v?: string | null) {
  if (!v) return '-'
  return String(v).slice(0, 19).replace('T', ' ')
}

export function fmtDate(v?: string | null) {
  const s = fmtTime(v)
  return s === '-' ? '-' : s.slice(0, 10)
}

/** 扫描引擎返回 UTC ISO，统一换算为北京时间展示 */
export function fmtTimeUtc8(v?: string | null) {
  if (!v) return '-'
  const d = new Date(v)
  if (Number.isNaN(d.getTime())) return fmtTime(v)
  const bj = new Date(d.getTime() + 8 * 3600 * 1000)
  return bj.toISOString().slice(0, 19).replace('T', ' ')
}

/** 从漏洞地址/域名提取主机名（与 core/asset_sync.extract_host 同口径） */
export function extractHost(address?: string | null): string {
  if (!address) return ''
  let s = String(address).trim().split(/\r?\n/)[0].trim()
  if (!s) return ''
  s = s.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, '')
  if (s.includes('@')) s = s.split('@').pop() || ''
  const m = s.match(/[/?#\s]/)
  if (m && m.index !== undefined) s = s.slice(0, m.index)
  if (!s) return ''
  if (s.startsWith('[')) {
    const e = s.indexOf(']')
    return e > 0 ? s.slice(1, e) : ''
  }
  if (s.includes(':')) {
    const i = s.lastIndexOf(':')
    if (/^\d+$/.test(s.slice(i + 1))) s = s.slice(0, i)
  }
  s = s.replace(/^\.+|\.+$/g, '').trim().toLowerCase()
  if (!s) return ''
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(s)) {
    return s.split('.').every((n) => +n >= 0 && +n <= 255) ? s : ''
  }
  const label = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/
  if (!s.split('.').every((p) => label.test(p))) return ''
  return /[a-z]/.test(s) ? s : ''
}

export function truncate(v?: string | null, max = 40) {
  const s = v || ''
  return s.length > max ? s.slice(0, max) + '…' : s
}

/** 按行/逗号拆分文本为去空数组（去重保序） */
export function splitLines(text: string, dedupe = true): string[] {
  const items = text
    .split(/\r?\n/)
    .map((x) => x.trim())
    .filter(Boolean)
  return dedupe ? Array.from(new Set(items)) : items
}

export function formatNumber(n?: number | null) {
  if (n === null || n === undefined || Number.isNaN(n)) return '0'
  return n.toLocaleString('zh-CN')
}
