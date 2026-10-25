import { useCallback, useEffect, useState } from 'react'
import {
  Database,
  Download,
  FileSpreadsheet,
  FileText,
  ListChecks,
  Plus,
  RefreshCw,
  Search,
  Upload,
} from 'lucide-react'
import { Card } from '@/components/ui/card'
import { DataTable, KV, type Column } from '@/components/ui/table'
import { SeverityBadge, TagChip } from '@/components/ui/badge'
import { Button, LinkButton } from '@/components/ui/button'
import { Checkbox, Field, Input, Select, Textarea } from '@/components/ui/field'
import { Modal } from '@/components/ui/modal'
import { EmptyState, Pagination } from '@/components/ui/states'
import { useConfirm } from '@/components/ui/confirm'
import { useToast } from '@/components/ui/toast'
import { api, downloadFile, ensureCsrf, pickFile } from '@/lib/api'
import { useQuery } from '@/lib/use-query'

const LIMIT = 10

interface Unit {
  id: number
  enterprise_name: string
  business_status?: string
  legal_representative?: string
  registered_capital?: string
  paid_in_capital?: string
  province?: string
  city?: string
  district?: string
  credit_code?: string
  industry?: string
  former_names?: string
  registered_address?: string
  filing_status?: string
  icp_total?: number
  domain_count?: number
  created_at?: string
  updated_at?: string
  tag_names?: string[]
}

interface TagOption {
  id: number
  name: string
}

/** /api/units/report-ids 返回的报告条目 */
interface UnitReport {
  id: number
  unit_name: string
  system_name?: string
  vul_name: string
  severity: string
}

interface TemplateItem {
  id: number
  name: string
  is_default?: number
}

interface UnitForm {
  enterprise_name: string
  business_status: string
  legal_representative: string
  registered_capital: string
  paid_in_capital: string
  credit_code: string
  province: string
  city: string
  district: string
  industry: string
  former_names: string
  filing_status: string
  icp_total: string
  domain_count: string
  registered_address: string
}

const EMPTY_UNIT_FORM: UnitForm = {
  enterprise_name: '',
  business_status: '',
  legal_representative: '',
  registered_capital: '',
  paid_in_capital: '',
  credit_code: '',
  province: '',
  city: '',
  district: '',
  industry: '',
  former_names: '',
  filing_status: 'unknown',
  icp_total: '',
  domain_count: '',
  registered_address: '',
}

const FILING_LABEL: Record<string, string> = {
  has_filing: '有备案信息',
  no_filing: '无备案信息',
  unknown: '未开始查询',
}

function filingLabel(v?: string | null) {
  if (!v) return '-'
  return FILING_LABEL[v] || v
}

function numText(v?: number | null) {
  return typeof v === 'number' && v >= 0 ? v : '-'
}

type ExportFmt = 'docx' | 'pdf'

const TPL_OPTIONS: Record<ExportFmt, Array<{ value: string; label: string }>> = {
  docx: [
    { value: 'custom', label: '标准模板（占位符自动填充，与原工具一致）' },
    { value: 'normal', label: '普通模板（漏洞详情排版）' },
    { value: 'gongwen', label: '网信办公文（仅单条）' },
    { value: 'summary', label: '汇总模板（多漏洞清单）' },
  ],
  pdf: [
    { value: 'normal', label: '普通模板（漏洞详情排版）' },
    { value: 'gongwen', label: '网信办公文（仅单条）' },
    { value: 'summary', label: '汇总模板（多漏洞清单）' },
  ],
}

/**
 * /api/units/import-icp 直接返回「单位名 → 结果」的裸对象（没有 code/msg 信封），
 * 与 api 客户端的统一响应约定不兼容，这里单独发一次同源请求（仍需 CSRF Token）。
 */
async function postRawJson(path: string, payload: unknown): Promise<Record<string, unknown>> {
  const token = await ensureCsrf()
  const resp = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
    body: JSON.stringify(payload),
    credentials: 'same-origin',
  })
  const parsed: unknown = await resp.json().catch(() => null)
  const obj = parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : null
  if (!resp.ok) {
    const msg = obj && typeof obj.msg === 'string' ? obj.msg : `请求失败（${resp.status}）`
    throw new Error(msg)
  }
  if (!obj) throw new Error('服务返回了非 JSON 响应')
  if (typeof obj.code === 'number' && obj.code !== 0) {
    throw new Error(typeof obj.msg === 'string' ? obj.msg : '导入失败')
  }
  return obj
}

export function Units() {
  const toast = useToast()
  const confirm = useConfirm()

  // ---------------- 列表查询 ----------------
  const [keyword, setKeyword] = useState('')
  const [committedKeyword, setCommittedKeyword] = useState('')
  const [tagId, setTagId] = useState('')
  const [page, setPage] = useState(1)
  const [selectedIds, setSelectedIds] = useState<number[]>([])
  const [tagOptions, setTagOptions] = useState<TagOption[]>([])

  const load = useCallback(async () => {
    const res = await api.get<Unit[]>('/api/units', {
      page,
      limit: LIMIT,
      enterprise_name: committedKeyword,
      tag_id: tagId,
    })
    return { rows: res.data || [], total: res.count || 0 }
  }, [page, committedKeyword, tagId])

  const { data, loading, error, reload } = useQuery(load, [load])
  const rows = data?.rows || []

  const loadTagOptions = useCallback(async () => {
    try {
      const res = await api.get<TagOption[]>('/api/tags/options')
      setTagOptions(res.data || [])
    } catch {
      // 标签选项加载失败不阻塞列表（与旧页面一致：静默忽略）
    }
  }, [])

  useEffect(() => {
    void loadTagOptions()
  }, [loadTagOptions])

  /** 新增/导入/同步后回到第 1 页并刷新 */
  function goFirstPage() {
    if (page === 1) void reload()
    else setPage(1)
  }

  /** 搜索：按输入框当前内容 + 当前标签条件重新查询（与旧页面 loadUnits(1) 一致） */
  function applyFilters(nextTagId?: string) {
    const kw = keyword.trim()
    if (nextTagId !== undefined) setTagId(nextTagId)
    const sameTag = nextTagId === undefined || nextTagId === tagId
    if (page === 1 && kw === committedKeyword && sameTag) {
      void reload()
      return
    }
    setPage(1)
    setCommittedKeyword(kw)
  }

  /** 跨页累计勾选：DataTable 只回传本页勾选，需要与已累计的集合合并 */
  function handleSelectedChange(keys: Array<string | number>) {
    const pageIds = rows.map((r) => r.id)
    const kept = selectedIds.filter((id) => !pageIds.includes(id))
    const added: number[] = []
    keys.forEach((k) => {
      const id = typeof k === 'number' ? k : Number(k)
      if (Number.isFinite(id) && !kept.includes(id) && !added.includes(id)) added.push(id)
    })
    setSelectedIds([...kept, ...added])
  }

  // ---------------- 新增（多行批量） ----------------
  const [addOpen, setAddOpen] = useState(false)
  const [addText, setAddText] = useState('')
  const [adding, setAdding] = useState(false)

  async function doAdd() {
    if (!addText.trim()) {
      toast.error('请输入单位名称')
      return
    }
    setAdding(true)
    try {
      const res = await api.post('/api/units/add', { enterprise_name: addText })
      toast.success(res.msg || '导入完成')
      setAddOpen(false)
      setAddText('')
      goFirstPage()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '导入失败')
    } finally {
      setAdding(false)
    }
  }

  // ---------------- 详情 ----------------
  const [detail, setDetail] = useState<Unit | null>(null)

  async function openDetail(id: number) {
    try {
      const res = await api.get<Unit>('/api/unit/detail', { id })
      setDetail(res.data || null)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '读取失败')
    }
  }

  // ---------------- 编辑 ----------------
  const [editOpen, setEditOpen] = useState(false)
  const [editId, setEditId] = useState<number | null>(null)
  const [editForm, setEditForm] = useState<UnitForm>(EMPTY_UNIT_FORM)
  const [savingEdit, setSavingEdit] = useState(false)

  async function openEdit(id: number) {
    try {
      const res = await api.get<Unit>('/api/unit/detail', { id })
      const u = res.data
      if (!u) {
        toast.error('单位不存在')
        return
      }
      setEditId(id)
      setEditForm({
        enterprise_name: u.enterprise_name || '',
        business_status: u.business_status || '',
        legal_representative: u.legal_representative || '',
        registered_capital: u.registered_capital || '',
        paid_in_capital: u.paid_in_capital || '',
        credit_code: u.credit_code || '',
        province: u.province || '',
        city: u.city || '',
        district: u.district || '',
        industry: u.industry || '',
        former_names: u.former_names || '',
        filing_status: u.filing_status || 'unknown',
        icp_total: typeof u.icp_total === 'number' ? String(u.icp_total) : '',
        domain_count: typeof u.domain_count === 'number' ? String(u.domain_count) : '',
        registered_address: u.registered_address || '',
      })
      setEditOpen(true)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '读取失败')
    }
  }

  async function saveEdit() {
    if (editId === null) return
    setSavingEdit(true)
    try {
      const res = await api.post('/api/unit/update', { id: editId, ...editForm })
      toast.success(res.msg || '更新成功')
      setEditOpen(false)
      await reload()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '更新失败')
    } finally {
      setSavingEdit(false)
    }
  }

  // ---------------- 删除 ----------------
  async function removeUnit(u: Unit) {
    const ok = await confirm({
      message: `确定删除单位「${u.enterprise_name}」？该操作不可恢复。`,
      confirmText: '删除',
    })
    if (!ok) return
    try {
      const res = await api.post('/api/unit/delete', { id: u.id })
      toast.success(res.msg || '已删除')
      setSelectedIds((prev) => prev.filter((id) => id !== u.id))
      if (rows.length === 1 && page > 1) setPage(page - 1)
      else await reload()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '删除失败')
    }
  }

  // ---------------- 设置单位标签 ----------------
  const [tagsOpen, setTagsOpen] = useState(false)
  const [tagsUnit, setTagsUnit] = useState<Unit | null>(null)
  const [unitTagIds, setUnitTagIds] = useState<number[]>([])
  const [newTagName, setNewTagName] = useState('')
  const [savingTags, setSavingTags] = useState(false)

  async function openUnitTags(u: Unit) {
    try {
      const [o, c] = await Promise.all([
        api.get<TagOption[]>('/api/tags/options'),
        api.get<{ tag_ids: number[] }>('/api/unit/tags', { unit_id: u.id }),
      ])
      setTagOptions(o.data || [])
      setUnitTagIds(((c.data && c.data.tag_ids) || []).map(Number))
      setTagsUnit(u)
      setNewTagName('')
      setTagsOpen(true)
    } catch {
      toast.error('加载标签失败')
    }
  }

  async function saveUnitTags() {
    if (!tagsUnit) return
    setSavingTags(true)
    try {
      const ids = [...unitTagIds]
      const name = newTagName.trim()
      if (name) {
        const ar = await api.post('/api/tags/add', { name })
        const tid = Number(ar.tag_id)
        if (!Number.isFinite(tid) || tid <= 0) {
          toast.error(ar.msg || '标签创建失败')
          return
        }
        ids.push(tid)
        void loadTagOptions()
      }
      const res = await api.post('/api/unit/set-tags', { unit_id: tagsUnit.id, tag_ids: ids })
      toast.success(res.msg || '标签已保存')
      setTagsOpen(false)
      await reload()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '保存标签失败')
    } finally {
      setSavingTags(false)
    }
  }

  // ---------------- 从存量报告同步 ----------------
  const [syncing, setSyncing] = useState(false)

  async function syncFromReports() {
    const ok = await confirm({
      message:
        '将扫描全部漏洞报告，把其中的单位、域名补录到资产库（已存在的不会重复添加），并回写各单位域名数量。是否继续？',
      confirmText: '开始同步',
      danger: false,
    })
    if (!ok) return
    setSyncing(true)
    try {
      const res = await api.post('/api/units/sync-from-reports', {})
      toast.success(res.msg || '同步完成')
      goFirstPage()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '同步失败')
    } finally {
      setSyncing(false)
    }
  }

  // ---------------- Excel 批量导入 / 更新 ----------------
  const [excelOpen, setExcelOpen] = useState(false)
  const [excelFile, setExcelFile] = useState<File | null>(null)
  const [importing, setImporting] = useState(false)

  async function chooseExcel() {
    const files = await pickFile('.xlsx,.xls')
    if (files && files[0]) setExcelFile(files[0])
  }

  async function doImportExcel() {
    if (!excelFile) {
      toast.error('请选择 Excel 文件')
      return
    }
    setImporting(true)
    try {
      const fd = new FormData()
      fd.append('file', excelFile)
      // 文件上传走 multipart，CSRF Token 由表单字段携带（后端同时接受 form.csrf_token）
      fd.append('csrf_token', await ensureCsrf())
      const res = await api.upload('/api/units/update', fd)
      toast.success(res.msg || '导入完成')
      setExcelOpen(false)
      setExcelFile(null)
      goFirstPage()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '导入失败')
    } finally {
      setImporting(false)
    }
  }

  // ---------------- 批量查询 ----------------
  const [bqOpen, setBqOpen] = useState(false)
  const [bqText, setBqText] = useState('')
  const [bqLoading, setBqLoading] = useState(false)
  const [bqResult, setBqResult] = useState<Unit[] | null>(null)

  async function doBatchQuery() {
    const values = bqText
      .split(/[\n,，]+/)
      .map((s) => s.trim())
      .filter(Boolean)
    if (!values.length) {
      toast.error('请输入查询内容')
      return
    }
    setBqLoading(true)
    try {
      const res = await api.post<Unit[]>('/api/unit/batch-query', { values })
      const list = res.data || []
      if (!list.length) {
        toast.info('未查询到匹配单位')
        return
      }
      setBqOpen(false)
      setBqResult(list)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '查询失败')
    } finally {
      setBqLoading(false)
    }
  }

  // ---------------- ICP 数据包导入 ----------------
  const [icpOpen, setIcpOpen] = useState(false)
  const [icpText, setIcpText] = useState('')
  const [icpLoading, setIcpLoading] = useState(false)
  const [icpResult, setIcpResult] = useState<Record<string, unknown> | null>(null)

  async function doIcpImport() {
    if (!icpText.trim()) {
      toast.error('请输入数据包')
      return
    }
    setIcpLoading(true)
    try {
      const result = await postRawJson('/api/units/import-icp', { data: icpText })
      if (!Object.keys(result).length) {
        toast.info('未解析到有效数据')
      } else {
        setIcpOpen(false)
        setIcpResult(result)
      }
      goFirstPage()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '导入失败')
    } finally {
      setIcpLoading(false)
    }
  }

  // ---------------- 批量导出 ----------------
  const [exportOpen, setExportOpen] = useState(false)
  const [reportOpen, setReportOpen] = useState(false)
  const [unitReports, setUnitReports] = useState<UnitReport[]>([])
  const [defaultTplId, setDefaultTplId] = useState<number | string>('')
  const [exportFmt, setExportFmt] = useState<ExportFmt>('docx')
  const [exportTplKey, setExportTplKey] = useState('custom')
  const [orgFooter, setOrgFooter] = useState('')
  const [exporting, setExporting] = useState(false)

  /** 导出单位名单：有勾选按 ids，未勾选按当前搜索 / 标签条件 */
  function exportRoster() {
    const ids = selectedIds.join(',')
    const q = ids
      ? `ids=${ids}`
      : `enterprise_name=${encodeURIComponent(keyword.trim())}&tag_id=${encodeURIComponent(tagId)}`
    downloadFile(`/api/units/export?${q}`)
    toast.success('开始下载单位名单 Excel')
  }

  function changeFmt(fmt: ExportFmt) {
    setExportFmt(fmt)
    setExportTplKey(TPL_OPTIONS[fmt][0].value)
  }

  async function openUnitReportExport() {
    if (!selectedIds.length) {
      toast.error('请先在列表勾选要导出报告的单位')
      return
    }
    try {
      const res = await api.get<UnitReport[]>('/api/units/report-ids', { ids: selectedIds.join(',') })
      const list = res.data || []
      // 默认排版模板（取默认模板，否则取第一个）
      let tplList: TemplateItem[] = []
      try {
        const tl = await api.get<TemplateItem[]>('/api/report/templates')
        tplList = tl.data || []
      } catch {
        tplList = []
      }
      const def = tplList.find((t) => t.is_default) || tplList[0]
      setDefaultTplId(def ? def.id : '')
      setUnitReports(list)
      if (!list.length) {
        toast.info('这些单位名下还没有漏洞报告，可先到「AI 智能生成」或「报告管理」录入')
        return
      }
      setExportFmt('docx')
      setExportTplKey('custom')
      setOrgFooter('')
      setExportOpen(false)
      setReportOpen(true)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '查询单位报告失败')
    }
  }

  async function doUnitReportExport() {
    const ids = unitReports.map((r) => r.id)
    const tplKey = exportTplKey
    if (tplKey === 'gongwen' && ids.length !== 1) {
      toast.error('公文模板仅支持单条报告，请只勾选对应一份报告的单位')
      return
    }
    if (exportFmt === 'pdf' && tplKey === 'custom') {
      toast.error('PDF 暂不支持自定义模板，请选其他模板或改用 Word')
      return
    }
    setExporting(true)
    try {
      const path = exportFmt === 'pdf' ? '/api/report/export-pdf' : '/api/report/export'
      const res = await api.post(path, {
        report_ids: ids,
        template_key: tplKey,
        template_id: tplKey === 'custom' ? defaultTplId : '',
        org_footer: orgFooter.trim(),
      })
      const url = typeof res.url === 'string' ? res.url : ''
      if (!url) {
        toast.error('导出失败：未获取到下载地址')
        return
      }
      toast.success('生成成功，开始下载')
      setReportOpen(false)
      window.setTimeout(() => downloadFile(url), 400)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '导出失败')
    } finally {
      setExporting(false)
    }
  }

  // ---------------- 表格列 ----------------
  const columns: Column<Unit>[] = [
    { key: 'id', title: 'ID', width: 64, render: (u) => <span className="tnum text-slate-500">{u.id}</span> },
    {
      key: 'enterprise_name',
      title: '企业名称',
      render: (u) => <span className="font-semibold text-slate-800">{u.enterprise_name}</span>,
    },
    { key: 'business_status', title: '经营状态', render: (u) => u.business_status || '-' },
    { key: 'legal_representative', title: '法定代表人', render: (u) => u.legal_representative || '-' },
    { key: 'registered_capital', title: '注册资本', render: (u) => u.registered_capital || '-' },
    { key: 'region', title: '地区', render: (u) => `${u.province || ''}${u.city || ''}` },
    {
      key: 'icp_total',
      title: 'ICP 备案数',
      width: 96,
      render: (u) => <span className="tnum">{numText(u.icp_total)}</span>,
    },
    {
      key: 'tag_names',
      title: '标签',
      className: 'max-w-[150px]',
      render: (u) =>
        u.tag_names && u.tag_names.length ? (
          <div className="flex flex-wrap gap-1">
            {u.tag_names.map((t) => (
              <TagChip key={t}>{t}</TagChip>
            ))}
          </div>
        ) : (
          <span className="text-slate-400">-</span>
        ),
    },
    {
      key: 'actions',
      title: '操作',
      width: 190,
      render: (u) => (
        <div className="flex items-center gap-3">
          <LinkButton onClick={() => openDetail(u.id)}>详情</LinkButton>
          <LinkButton onClick={() => openUnitTags(u)}>标签</LinkButton>
          <LinkButton onClick={() => openEdit(u.id)}>编辑</LinkButton>
          <LinkButton danger onClick={() => removeUnit(u)}>
            删除
          </LinkButton>
        </div>
      ),
    },
  ]

  const reportColumns: Column<UnitReport>[] = [
    { key: 'id', title: 'ID', width: 56, render: (r) => <span className="tnum text-slate-500">{r.id}</span> },
    {
      key: 'unit_name',
      title: '单位',
      render: (r) => <span className="font-semibold text-slate-800">{r.unit_name}</span>,
    },
    { key: 'vul_name', title: '漏洞名称', render: (r) => r.vul_name },
    { key: 'severity', title: '等级', width: 76, render: (r) => <SeverityBadge severity={r.severity} /> },
  ]

  const batchQueryColumns: Column<Unit>[] = [
    {
      key: 'enterprise_name',
      title: '企业名称',
      render: (u) => <span className="font-semibold text-slate-800">{u.enterprise_name}</span>,
    },
    { key: 'business_status', title: '状态', render: (u) => u.business_status || '-' },
    { key: 'region', title: '地区', render: (u) => `${u.province || ''}${u.city || ''}` },
    {
      key: 'icp_total',
      title: 'ICP备案数',
      width: 100,
      render: (u) => <span className="tnum">{numText(u.icp_total)}</span>,
    },
  ]

  const selectedCount = selectedIds.length

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <div className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-3">
          <Input
            value={keyword}
            onChange={(e) => setKeyword(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') applyFilters()
            }}
            placeholder="按企业名称搜索..."
            className="w-[220px]"
          />
          <Select
            value={tagId}
            onChange={(e) => applyFilters(e.target.value)}
            className="w-[150px]"
            aria-label="标签筛选"
          >
            <option value="">全部标签</option>
            {tagOptions.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name}
              </option>
            ))}
          </Select>
          <Button variant="primary" icon={<Search size={14} />} onClick={() => applyFilters()}>
            搜索
          </Button>
          <span className="flex-1" />
          <Button
            variant="ghost"
            size="sm"
            icon={<Download size={13} />}
            onClick={() => downloadFile('/api/units/template')}
          >
            下载导入模板
          </Button>
          <Button
            variant="ghost"
            size="sm"
            icon={<Upload size={13} />}
            onClick={() => {
              setExcelFile(null)
              setExcelOpen(true)
            }}
          >
            Excel 批量导入
          </Button>
          <Button
            variant="ghost"
            size="sm"
            icon={<Database size={13} />}
            onClick={() => {
              setIcpText('')
              setIcpOpen(true)
            }}
          >
            ICP 数据导入
          </Button>
          <Button
            variant="ghost"
            size="sm"
            icon={<ListChecks size={13} />}
            onClick={() => {
              setBqText('')
              setBqOpen(true)
            }}
          >
            批量查询
          </Button>
          <Button
            variant="ghost"
            size="sm"
            icon={<RefreshCw size={13} />}
            loading={syncing}
            onClick={syncFromReports}
            title="把已有漏洞报告里的单位、域名一键补录到资产库（不会重复添加）"
          >
            从报告同步资产
          </Button>
          <Button
            variant="success"
            size="sm"
            icon={<FileText size={13} />}
            onClick={() => setExportOpen(true)}
          >
            批量导出
            <span className="ml-0.5 inline-flex h-4 min-w-4 items-center justify-center rounded bg-emerald-700 px-1 text-[11px] font-medium text-white">
              {selectedCount}
            </span>
          </Button>
          <Button
            variant="primary"
            size="sm"
            icon={<Plus size={13} />}
            onClick={() => {
              setAddText('')
              setAddOpen(true)
            }}
          >
            新增单位
          </Button>
        </div>

        <DataTable
          columns={columns}
          rows={rows}
          rowKey={(u) => u.id}
          loading={loading}
          selectable
          selectedKeys={selectedIds}
          onSelectedChange={handleSelectedChange}
          empty={
            <EmptyState
              title="暂无单位数据"
              description="可点击右上角「新增单位」批量录入，或使用「Excel 批量导入」"
              action={
                <Button
                  size="sm"
                  variant="primary"
                  onClick={() => {
                    setAddText('')
                    setAddOpen(true)
                  }}
                >
                  新增单位
                </Button>
              }
            />
          }
        />

        {error ? <p className="px-4 pb-2 text-xs text-red-600">{error}</p> : null}

        <div className="border-t border-line px-4 py-3">
          <Pagination page={page} total={data?.total || 0} limit={LIMIT} onChange={setPage} />
        </div>
      </Card>

      {/* 新增（多行批量） */}
      <Modal
        open={addOpen}
        onClose={() => setAddOpen(false)}
        title="新增单位（每行一个）"
        size="md"
        footer={
          <>
            <Button onClick={() => setAddOpen(false)}>取消</Button>
            <Button variant="primary" loading={adding} onClick={doAdd}>
              导入
            </Button>
          </>
        }
      >
        <Field label="企业名称" required>
          <Textarea
            rows={8}
            value={addText}
            onChange={(e) => setAddText(e.target.value)}
            placeholder="每行一个单位名称，支持批量粘贴"
          />
        </Field>
      </Modal>

      {/* 详情 */}
      <Modal
        open={!!detail}
        onClose={() => setDetail(null)}
        title="单位详情"
        size="md"
        footer={
          <Button variant="primary" onClick={() => setDetail(null)}>
            关闭
          </Button>
        }
      >
        {detail ? (
          <div>
            <KV label="企业名称">{detail.enterprise_name || '-'}</KV>
            <KV label="经营状态">{detail.business_status || '-'}</KV>
            <KV label="法定代表人">{detail.legal_representative || '-'}</KV>
            <KV label="注册资本">{detail.registered_capital || '-'}</KV>
            <KV label="实缴资本">{detail.paid_in_capital || '-'}</KV>
            <KV label="所属省份/城市/区县">
              {`${detail.province || ''} ${detail.city || ''} ${detail.district || ''}`}
            </KV>
            <KV label="统一社会信用代码">{detail.credit_code || '-'}</KV>
            <KV label="所属行业">{detail.industry || '-'}</KV>
            <KV label="曾用名">{detail.former_names || '-'}</KV>
            <KV label="注册地址">{detail.registered_address || '-'}</KV>
            <KV label="备案状态">{filingLabel(detail.filing_status)}</KV>
            <KV label="ICP 备案数">{numText(detail.icp_total)}</KV>
            <KV label="域名备案数">{numText(detail.domain_count)}</KV>
          </div>
        ) : null}
      </Modal>

      {/* 编辑 */}
      <Modal
        open={editOpen}
        onClose={() => setEditOpen(false)}
        title="编辑单位"
        size="lg"
        footer={
          <>
            <Button onClick={() => setEditOpen(false)}>取消</Button>
            <Button variant="primary" loading={savingEdit} onClick={saveEdit}>
              保存
            </Button>
          </>
        }
      >
        <div className="grid gap-3.5 sm:grid-cols-2">
          <Field label="企业名称">
            <Input
              value={editForm.enterprise_name}
              onChange={(e) => setEditForm({ ...editForm, enterprise_name: e.target.value })}
              placeholder="必填"
            />
          </Field>
          <Field label="经营状态">
            <Input
              value={editForm.business_status}
              onChange={(e) => setEditForm({ ...editForm, business_status: e.target.value })}
            />
          </Field>
          <Field label="法定代表人">
            <Input
              value={editForm.legal_representative}
              onChange={(e) => setEditForm({ ...editForm, legal_representative: e.target.value })}
            />
          </Field>
          <Field label="注册资本">
            <Input
              value={editForm.registered_capital}
              onChange={(e) => setEditForm({ ...editForm, registered_capital: e.target.value })}
            />
          </Field>
          <Field label="实缴资本">
            <Input
              value={editForm.paid_in_capital}
              onChange={(e) => setEditForm({ ...editForm, paid_in_capital: e.target.value })}
            />
          </Field>
          <Field label="统一社会信用代码">
            <Input
              value={editForm.credit_code}
              onChange={(e) => setEditForm({ ...editForm, credit_code: e.target.value })}
            />
          </Field>
          <Field label="省份">
            <Input value={editForm.province} onChange={(e) => setEditForm({ ...editForm, province: e.target.value })} />
          </Field>
          <Field label="城市">
            <Input value={editForm.city} onChange={(e) => setEditForm({ ...editForm, city: e.target.value })} />
          </Field>
          <Field label="区县">
            <Input value={editForm.district} onChange={(e) => setEditForm({ ...editForm, district: e.target.value })} />
          </Field>
          <Field label="所属行业">
            <Input value={editForm.industry} onChange={(e) => setEditForm({ ...editForm, industry: e.target.value })} />
          </Field>
          <Field label="曾用名">
            <Input
              value={editForm.former_names}
              onChange={(e) => setEditForm({ ...editForm, former_names: e.target.value })}
            />
          </Field>
          <Field label="备案状态">
            <Select
              value={editForm.filing_status}
              onChange={(e) => setEditForm({ ...editForm, filing_status: e.target.value })}
            >
              <option value="unknown">未开始查询</option>
              <option value="has_filing">有备案信息</option>
              <option value="no_filing">无备案信息</option>
            </Select>
          </Field>
          <Field label="ICP 官网备案数量">
            <Input
              value={editForm.icp_total}
              onChange={(e) => setEditForm({ ...editForm, icp_total: e.target.value })}
            />
          </Field>
          <Field label="数据库备案数量">
            <Input
              value={editForm.domain_count}
              onChange={(e) => setEditForm({ ...editForm, domain_count: e.target.value })}
            />
          </Field>
          <Field label="注册地址" className="sm:col-span-2">
            <Textarea
              rows={3}
              value={editForm.registered_address}
              onChange={(e) => setEditForm({ ...editForm, registered_address: e.target.value })}
            />
          </Field>
        </div>
      </Modal>

      {/* 设置单位标签 */}
      <Modal
        open={tagsOpen}
        onClose={() => setTagsOpen(false)}
        title="设置单位标签"
        size="md"
        footer={
          <>
            <Button onClick={() => setTagsOpen(false)}>取消</Button>
            <Button variant="primary" loading={savingTags} onClick={saveUnitTags}>
              保存
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-2">
          {tagsUnit ? (
            <p className="text-xs text-slate-500">当前单位：{tagsUnit.enterprise_name}</p>
          ) : null}
          {tagOptions.length ? (
            <div className="max-h-[46vh] overflow-auto rounded-md border border-line p-1">
              {tagOptions.map((t) => (
                <div key={t.id} className="border-b border-line px-2 py-1.5 last:border-0">
                  <Checkbox
                    label={<TagChip>{t.name}</TagChip>}
                    checked={unitTagIds.includes(t.id)}
                    onChange={(e) =>
                      setUnitTagIds(
                        e.target.checked ? [...unitTagIds, t.id] : unitTagIds.filter((x) => x !== t.id),
                      )
                    }
                  />
                </div>
              ))}
            </div>
          ) : (
            <p className="px-1.5 py-2.5 text-[13px] text-slate-400">
              还没有标签，在下方输入名称后点保存即可自动创建并关联
            </p>
          )}
          <Input
            value={newTagName}
            onChange={(e) => setNewTagName(e.target.value)}
            placeholder="没有合适标签？输入新标签名称（可选）"
          />
        </div>
      </Modal>

      {/* 批量导出 */}
      <Modal
        open={exportOpen}
        onClose={() => setExportOpen(false)}
        title="批量导出"
        size="md"
        footer={<Button onClick={() => setExportOpen(false)}>关闭</Button>}
      >
        <div className="flex flex-col gap-3">
          <p className="text-[13px] text-slate-600">
            已勾选 <span className="tnum text-[17px] font-semibold text-primary">{selectedCount}</span> 个单位（可跨页累计勾选）。
          </p>
          <button
            type="button"
            onClick={exportRoster}
            className="rounded-lg border border-line px-4 py-3.5 text-left transition-colors hover:border-primary hover:bg-primary-soft"
          >
            <span className="flex items-center gap-2 text-[13.5px] font-semibold text-slate-800">
              <FileSpreadsheet size={15} className="text-emerald-600" />
              导出单位名单（Excel）
            </span>
            <span className="mt-1 block text-xs leading-6 text-slate-500">
              {selectedCount
                ? `导出勾选的 ${selectedCount} 个单位的完整工商 / 备案 / 标签信息`
                : '未勾选时，导出当前搜索 / 标签条件下的全部单位'}
            </span>
          </button>
          <button
            type="button"
            onClick={openUnitReportExport}
            className="rounded-lg border border-line px-4 py-3.5 text-left transition-colors hover:border-emerald-600 hover:bg-emerald-50"
          >
            <span className="flex items-center gap-2 text-[13.5px] font-semibold text-slate-800">
              <FileText size={15} className="text-slate-500" />
              导出这些单位的漏洞报告（Word / PDF）
            </span>
            <span className="mt-1 block text-xs leading-6 text-slate-500">
              {selectedCount
                ? '自动汇总勾选单位名下的全部漏洞报告，选择模板后一次性导出'
                : '请先在列表勾选单位后再使用'}
            </span>
          </button>
          {selectedCount ? (
            <button
              type="button"
              onClick={() => {
                setSelectedIds([])
                setExportOpen(false)
              }}
              className="self-start text-[12.5px] text-primary hover:underline"
            >
              清空全部勾选
            </button>
          ) : null}
        </div>
      </Modal>

      {/* 按单位导出报告 */}
      <Modal
        open={reportOpen}
        onClose={() => setReportOpen(false)}
        title={`导出勾选单位的 ${unitReports.length} 份漏洞报告`}
        size="xl"
        footer={
          <>
            <Button onClick={() => setReportOpen(false)}>取消</Button>
            <Button variant="warning" loading={exporting} onClick={doUnitReportExport}>
              生成并下载
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-3">
          <div className="max-h-[240px] overflow-auto rounded-md border border-line">
            <DataTable
              columns={reportColumns}
              rows={unitReports.slice(0, 50)}
              rowKey={(r) => r.id}
            />
          </div>
          {unitReports.length > 50 ? (
            <p className="text-xs text-amber-600">列表仅预览前 50 条，实际导出全部 {unitReports.length} 条</p>
          ) : null}
          <div className="grid gap-3.5 sm:grid-cols-2">
            <Field label="导出格式">
              <Select
                value={exportFmt}
                onChange={(e) => changeFmt(e.target.value === 'pdf' ? 'pdf' : 'docx')}
              >
                <option value="docx">Word（.docx）</option>
                <option value="pdf">PDF（.pdf）</option>
              </Select>
            </Field>
            <Field label="排版模板">
              <Select value={exportTplKey} onChange={(e) => setExportTplKey(e.target.value)}>
                {TPL_OPTIONS[exportFmt].map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="报告落款单位（可选）" className="sm:col-span-2">
              <Input
                value={orgFooter}
                onChange={(e) => setOrgFooter(e.target.value)}
                placeholder="如：XX 网络安全测评中心"
              />
            </Field>
          </div>
        </div>
      </Modal>

      {/* Excel 批量导入 */}
      <Modal
        open={excelOpen}
        onClose={() => setExcelOpen(false)}
        title="Excel 批量导入 / 更新单位"
        size="md"
        footer={
          <>
            <Button onClick={() => setExcelOpen(false)}>取消</Button>
            <Button variant="primary" loading={importing} onClick={doImportExcel}>
              开始导入
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-3">
          <div className="text-[13px] leading-7 text-slate-500">
            1. 先下载「导入模板」填写数据
            <br />
            2. 上传 Excel，按「企业名称」匹配更新，不存在则新增；
            <br />
            3. 经营状态为注销/吊销等无效状态的新单位会自动跳过。
          </div>
          <div className="flex items-center gap-2">
            <Button size="sm" icon={<Upload size={13} />} onClick={chooseExcel}>
              选择 Excel 文件
            </Button>
            <span className="min-w-0 flex-1 truncate text-xs text-slate-500">
              {excelFile ? excelFile.name : '支持 .xlsx / .xls'}
            </span>
          </div>
        </div>
      </Modal>

      {/* 批量查询 */}
      <Modal
        open={bqOpen}
        onClose={() => setBqOpen(false)}
        title="批量查询单位"
        size="md"
        footer={
          <>
            <Button onClick={() => setBqOpen(false)}>取消</Button>
            <Button variant="primary" loading={bqLoading} onClick={doBatchQuery}>
              查询
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-2.5">
          <p className="text-[13px] text-slate-500">输入单位名称关键字（逗号/换行分隔），支持模糊匹配</p>
          <Textarea
            rows={6}
            value={bqText}
            onChange={(e) => setBqText(e.target.value)}
            placeholder={'示例公司A\n示例公司B'}
          />
        </div>
      </Modal>

      {/* 批量查询结果 */}
      <Modal
        open={!!bqResult}
        onClose={() => setBqResult(null)}
        title={`查询结果（${bqResult?.length || 0} 条）`}
        size="lg"
        footer={
          <Button variant="primary" onClick={() => setBqResult(null)}>
            关闭
          </Button>
        }
      >
        <DataTable
          columns={batchQueryColumns}
          rows={bqResult || []}
          rowKey={(u) => u.id}
          empty={<EmptyState title="未查询到匹配单位" />}
        />
      </Modal>

      {/* ICP 数据包导入 */}
      <Modal
        open={icpOpen}
        onClose={() => setIcpOpen(false)}
        title="ICP 备案数据包导入"
        size="lg"
        footer={
          <>
            <Button onClick={() => setIcpOpen(false)}>取消</Button>
            <Button variant="primary" loading={icpLoading} onClick={doIcpImport}>
              导入
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-2.5">
          <div className="text-[13px] leading-7 text-slate-500">
            支持两种格式：
            <br />
            ① 新格式：每行一个 JSON（含 query_keyword 与 result）
            <br />
            ② 旧格式：每行「企业名称: {'{JSON 数据包}'}」
            <br />
            导入后将更新对应单位的 ICP 备案数量，并自动同步域名资产。
          </div>
          <Textarea
            rows={10}
            value={icpText}
            onChange={(e) => setIcpText(e.target.value)}
            placeholder="粘贴 ICP 查询数据包，每行一条"
          />
        </div>
      </Modal>

      {/* ICP 导入结果 */}
      <Modal
        open={!!icpResult}
        onClose={() => setIcpResult(null)}
        title="导入结果"
        size="md"
        footer={
          <Button variant="primary" onClick={() => setIcpResult(null)}>
            关闭
          </Button>
        }
      >
        <div className="max-h-[50vh] overflow-y-auto">
          {icpResult
            ? Object.entries(icpResult).map(([name, value]) => (
                <KV key={name} label={name}>
                  {String(value)}
                </KV>
              ))
            : null}
        </div>
      </Modal>
    </div>
  )
}
