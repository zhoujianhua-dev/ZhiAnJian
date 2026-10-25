import { useCallback, useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { CheckCircle2, FilePlus2 } from 'lucide-react'
import { Badge, SeverityBadge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Field, Input } from '@/components/ui/field'
import { Modal } from '@/components/ui/modal'
import { LoadingBlock } from '@/components/ui/states'
import { SuggestInput } from '@/components/ui/suggest-input'
import { useToast } from '@/components/ui/toast'
import { api } from '@/lib/api'
import { extractHost, truncate } from '@/lib/format'
import { cn } from '@/lib/cn'

/** 扫描引擎统一发现格式（与后端 to_findings 输出一致） */
export interface ScanFinding {
  source?: string
  data?: {
    title?: string
    severity?: string
    url?: string
    evidence?: string
    description?: string
  }
}

interface ScanResultPayload {
  scan_id: string
  target: string
  unit_name?: string
  system_name?: string
  findings: ScanFinding[]
}

interface AddToReportsDialogProps {
  open: boolean
  onClose: () => void
  scanId: string
  target: string
  /** 已有结果时直接传入，避免重复请求；为空则打开时自动拉取 */
  findings?: ScanFinding[]
  defaultUnit?: string
  defaultSystem?: string
  onAdded?: (count: number) => void
}

/** 把扫描结果按「单位 + 系统」批量加入报告管理 */
export function AddToReportsDialog({
  open,
  onClose,
  scanId,
  target,
  findings,
  defaultUnit,
  defaultSystem,
  onAdded,
}: AddToReportsDialogProps) {
  const toast = useToast()
  const navigate = useNavigate()

  const [loaded, setLoaded] = useState<ScanFinding[]>([])
  const [loading, setLoading] = useState(false)
  const [loadError, setLoadError] = useState('')

  const [unit, setUnit] = useState('')
  const [system, setSystem] = useState('')
  const [domain, setDomain] = useState('')
  const [checked, setChecked] = useState<Set<number>>(new Set())
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [done, setDone] = useState<number | null>(null)

  const rows = findings && findings.length ? findings : loaded

  const loadFindings = useCallback(async () => {
    if (!scanId) return
    setLoading(true)
    setLoadError('')
    try {
      const res = await api.get<ScanResultPayload>(`/api/scanner/shelling/result/${encodeURIComponent(scanId)}`)
      const data = res.data as ScanResultPayload
      setLoaded(data.findings || [])
      // 后端已记录归属时优先回填（扫描时填过 / 之前加入报告时补录过）
      if (!defaultUnit && data.unit_name) setUnit(data.unit_name)
      if (!defaultSystem && data.system_name) setSystem(data.system_name)
    } catch (e) {
      setLoadError(e instanceof Error ? e.message : '读取扫描结果失败')
    } finally {
      setLoading(false)
    }
  }, [scanId, defaultUnit, defaultSystem])

  // 每次打开重置表单，避免上一次的勾选/成功态残留
  useEffect(() => {
    if (!open) return
    setUnit(defaultUnit || '')
    setSystem(defaultSystem || '')
    setDomain('')
    setError('')
    setDone(null)
    setChecked(new Set())
    if (findings && findings.length) {
      setLoaded([])
      setLoadError('')
      setLoading(false)
    } else {
      void loadFindings()
    }
  }, [open, defaultUnit, defaultSystem, findings, loadFindings])

  // 结果到位后默认全选
  useEffect(() => {
    if (!open || done !== null) return
    setChecked(new Set(rows.map((_, i) => i)))
  }, [open, rows, done])

  const allChecked = rows.length > 0 && checked.size === rows.length
  const selectedCount = checked.size

  const summary = useMemo(() => {
    const counts: Record<string, number> = {}
    rows.forEach((f) => {
      const key = f.data?.severity || 'unknown'
      counts[key] = (counts[key] || 0) + 1
    })
    return counts
  }, [rows])

  function toggle(index: number) {
    setChecked((prev) => {
      const next = new Set(prev)
      if (next.has(index)) next.delete(index)
      else next.add(index)
      return next
    })
  }

  function toggleAll() {
    setChecked(allChecked ? new Set() : new Set(rows.map((_, i) => i)))
  }

  async function submit() {
    setError('')
    if (!unit.trim()) {
      setError('请填写所属单位名称')
      return
    }
    if (!selectedCount) {
      setError('请至少选择一个漏洞')
      return
    }
    const picked = rows.filter((_, i) => checked.has(i))
    setSaving(true)
    try {
      const res = await api.post<{ ids: number[]; count: number }>('/api/report/batch-add', {
        unit_name: unit.trim(),
        system_name: system.trim(),
        domain: domain.trim(),
        findings: picked,
      })
      const count = res.data?.count ?? picked.length
      // 归属信息回写到扫描任务，下次打开直接回填（失败不影响主流程）
      api
        .post(`/api/scanner/shelling/meta/${encodeURIComponent(scanId)}`, {
          unit_name: unit.trim(),
          system_name: system.trim(),
        })
        .catch(() => undefined)
      toast.success(res.msg || `已加入 ${count} 条报告`)
      setDone(count)
      onAdded?.(count)
    } catch (e) {
      setError(e instanceof Error ? e.message : '加入报告失败')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="加入报告管理"
      size="lg"
      footer={
        done !== null ? (
          <>
            <Button variant="secondary" onClick={onClose}>
              关闭
            </Button>
            <Button variant="primary" onClick={() => navigate('/reports')}>
              前往报告管理
            </Button>
          </>
        ) : (
          <>
            <Button onClick={onClose}>取消</Button>
            <Button
              variant="primary"
              icon={<FilePlus2 size={14} />}
              loading={saving}
              disabled={loading || !rows.length}
              onClick={() => void submit()}
            >
              添加 {selectedCount} 条到报告管理
            </Button>
          </>
        )
      }
    >
      {done !== null ? (
        <div className="flex flex-col items-center gap-2 py-8 text-center">
          <CheckCircle2 size={36} className="text-emerald-500" />
          <p className="text-[14px] font-medium text-slate-800">已加入 {done} 条报告</p>
          <p className="text-xs text-slate-500">
            单位「{unit.trim() || '-'}」{system.trim() ? ` · 系统「${system.trim()}」` : ''}，可在「报告管理」继续编辑、导出与跟踪处置。
          </p>
        </div>
      ) : (
        <div className="flex flex-col gap-3.5">
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="所属单位名称" required hint="可直接选择已有单位，也可输入新单位（会自动登记）">
              <SuggestInput
                value={unit}
                onChange={setUnit}
                placeholder="如：XX 网络科技有限公司"
                load={async (kw) => {
                  const res = await api.get<Array<{ id: number; enterprise_name: string }>>('/api/unit/search', {
                    q: kw,
                  })
                  return (res.data || []).map((u) => u.enterprise_name).filter(Boolean)
                }}
              />
            </Field>
            <Field label="系统名称" hint="留空则报告里不填系统">
              <Input value={system} onChange={(e) => setSystem(e.target.value)} placeholder="如：官网 / 后台管理系统" />
            </Field>
            <Field label="域名（可选）" className="sm:col-span-2" hint={`留空则按漏洞地址自动识别，默认扫描目标：${target || '-'}`}>
              <Input
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder={extractHost(target) || '例如 example.com'}
              />
            </Field>
          </div>

          <div className="overflow-hidden rounded-md border border-line">
            <div className="flex flex-wrap items-center gap-2 border-b border-line bg-slate-50 px-3 py-2">
              <label className="inline-flex cursor-pointer select-none items-center gap-2 text-[13px] font-medium text-slate-700">
                <input
                  type="checkbox"
                  checked={allChecked}
                  onChange={toggleAll}
                  disabled={!rows.length}
                  className="h-3.5 w-3.5 rounded border-line-strong accent-[color:var(--primary)]"
                />
                选择要加入的漏洞
              </label>
              <span className="text-xs text-slate-500">
                已选 {selectedCount} / {rows.length}
              </span>
              <span className="flex-1" />
              <span className="flex flex-wrap items-center gap-1.5">
                {Object.entries(summary).map(([sev, n]) => (
                  <span key={sev} className="inline-flex items-center gap-1">
                    <SeverityBadge severity={sev} />
                    <span className="text-xs text-slate-500">×{n}</span>
                  </span>
                ))}
              </span>
            </div>

            {loading ? (
              <LoadingBlock text="正在读取扫描结果…" />
            ) : loadError ? (
              <p className="px-3 py-6 text-center text-[13px] text-red-600">{loadError}</p>
            ) : rows.length === 0 ? (
              <p className="px-3 py-6 text-center text-[13px] text-slate-400">本次扫描没有可加入的漏洞</p>
            ) : (
              <ul className="max-h-[280px] divide-y divide-line overflow-y-auto">
                {rows.map((f, i) => {
                  const d = f.data || {}
                  return (
                    <li key={`${d.title || 'f'}-${i}`}>
                      <label
                        className={cn(
                          'flex cursor-pointer items-start gap-2.5 px-3 py-2 transition-colors hover:bg-slate-50',
                          checked.has(i) && 'bg-primary-soft/40',
                        )}
                      >
                        <input
                          type="checkbox"
                          checked={checked.has(i)}
                          onChange={() => toggle(i)}
                          className="mt-1 h-3.5 w-3.5 shrink-0 rounded border-line-strong accent-[color:var(--primary)]"
                        />
                        <span className="min-w-0 flex-1">
                          <span className="flex flex-wrap items-center gap-1.5">
                            <SeverityBadge severity={d.severity} />
                            <span className="text-[13px] font-medium text-slate-800">
                              {d.title || '未知漏洞'}
                            </span>
                          </span>
                          {d.url ? (
                            <span className="mt-0.5 block truncate text-xs text-slate-500" title={d.url}>
                              {truncate(d.url, 90)}
                            </span>
                          ) : null}
                        </span>
                      </label>
                    </li>
                  )
                })}
              </ul>
            )}
          </div>

          <p className="text-xs leading-5 text-slate-400">
            加入后会自动登记所属单位与域名，并把漏洞写入漏洞库；可在「报告管理」继续补充检测过程截图、导出 Word/PDF。
          </p>

          {error ? <p className="text-[13px] text-red-600">{error}</p> : null}
        </div>
      )}
    </Modal>
  )
}
