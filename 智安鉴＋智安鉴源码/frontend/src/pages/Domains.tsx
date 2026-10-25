import { useCallback, useState } from 'react'
import { Building2, ListFilter, Plus, Search, Upload } from 'lucide-react'
import { Card } from '@/components/ui/card'
import { DataTable, type Column } from '@/components/ui/table'
import { Button, LinkButton } from '@/components/ui/button'
import { Field, Input, Select, Textarea } from '@/components/ui/field'
import { Modal } from '@/components/ui/modal'
import { EmptyState, ErrorBlock, Pagination } from '@/components/ui/states'
import { useConfirm } from '@/components/ui/confirm'
import { useToast } from '@/components/ui/toast'
import { api, type ApiResp } from '@/lib/api'
import { fmtTime } from '@/lib/format'
import { useQuery } from '@/lib/use-query'

const LIMIT = 10

interface Domain {
  id: number
  unit_name?: string
  domain: string
  main_licence?: string
  service_licence?: string
  nature_name?: string
  content_type_name?: string
  update_record_time?: string
  created_at?: string
}

interface DomainForm {
  unit_name: string
  domain: string
  main_licence: string
  service_licence: string
  nature_name: string
  content_type_name: string
  update_record_time: string
}

const EMPTY_FORM: DomainForm = {
  unit_name: '',
  domain: '',
  main_licence: '',
  service_licence: '',
  nature_name: '',
  content_type_name: '',
  update_record_time: '',
}

/** /api/domains/import-json 除标准字段外还返回导入统计 */
interface ImportExtra {
  success_count?: number
  error_count?: number
  errors?: string[]
}

type BatchType = 'unit' | 'domain'

/** 与旧页面一致的导入格式说明 */
const IMPORT_HELP: string[] = [
  '兼容三种格式：',
  '① 直接粘贴 JSON 数组：[{"domain": "...", "unitName": "...", ...}]',
  '② {"params": {"list": [...]}}',
  '③ {"result": {"params": {"list": [...]}}}',
  '已存在域名会自动更新信息，不重复入库。',
]

interface BatchRow {
  unit_name?: string
  domain: string
}

export function Domains() {
  const toast = useToast()
  const confirm = useConfirm()

  // 列表查询
  const [unitKeyword, setUnitKeyword] = useState('')
  const [domainKeyword, setDomainKeyword] = useState('')
  const [query, setQuery] = useState({ unitName: '', domain: '' })
  const [page, setPage] = useState(1)

  // 新增 / 编辑
  const [formOpen, setFormOpen] = useState(false)
  const [editingId, setEditingId] = useState<number | null>(null)
  const [form, setForm] = useState<DomainForm>(EMPTY_FORM)
  const [saving, setSaving] = useState(false)

  // ICP JSON 导入
  const [importOpen, setImportOpen] = useState(false)
  const [importText, setImportText] = useState('')
  const [importing, setImporting] = useState(false)
  const [importErrors, setImportErrors] = useState<string[] | null>(null)

  // 批量查询
  const [batchOpen, setBatchOpen] = useState(false)
  const [batchType, setBatchType] = useState<BatchType>('unit')
  const [batchText, setBatchText] = useState('')
  const [batchLoading, setBatchLoading] = useState(false)
  const [batchRows, setBatchRows] = useState<BatchRow[] | null>(null)

  // 按单位查域名
  const [unitOpen, setUnitOpen] = useState(false)
  const [unitName, setUnitName] = useState('')
  const [unitLoading, setUnitLoading] = useState(false)
  const [unitRows, setUnitRows] = useState<Domain[] | null>(null)
  const [unitQueried, setUnitQueried] = useState('')

  const load = useCallback(async () => {
    const res = await api.get<Domain[]>('/api/domains', {
      page,
      limit: LIMIT,
      unitName: query.unitName,
      domain: query.domain,
    })
    return { rows: res.data || [], total: res.count || 0 }
  }, [page, query])

  const { data, loading, error, reload } = useQuery(load, [load])

  function search() {
    setPage(1)
    setQuery({ unitName: unitKeyword.trim(), domain: domainKeyword.trim() })
  }

  /** 回到第一页并刷新（新增 / 导入后使用） */
  async function reloadFirstPage() {
    if (page === 1) await reload()
    else setPage(1)
  }

  function openAdd() {
    setEditingId(null)
    setForm(EMPTY_FORM)
    setFormOpen(true)
  }

  function openEdit(row: Domain) {
    setEditingId(row.id)
    setForm({
      unit_name: row.unit_name || '',
      domain: row.domain || '',
      main_licence: row.main_licence || '',
      service_licence: row.service_licence || '',
      nature_name: row.nature_name || '',
      content_type_name: row.content_type_name || '',
      update_record_time: row.update_record_time || '',
    })
    setFormOpen(true)
  }

  async function save() {
    const domain = form.domain.trim()
    if (!domain) {
      toast.error('请输入域名')
      return
    }
    setSaving(true)
    try {
      const base = {
        unit_name: form.unit_name.trim(),
        domain,
        main_licence: form.main_licence.trim(),
        service_licence: form.service_licence.trim(),
        nature_name: form.nature_name.trim(),
        content_type_name: form.content_type_name.trim(),
      }
      const res = editingId
        ? await api.post('/api/domains/edit', {
            id: editingId,
            ...base,
            update_record_time: form.update_record_time,
          })
        : await api.post('/api/domains/edit', base)
      toast.success(res.msg || (editingId ? '更新成功' : '新增成功'))
      setFormOpen(false)
      if (editingId) await reload()
      else await reloadFirstPage()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '保存失败')
    } finally {
      setSaving(false)
    }
  }

  async function remove(row: Domain) {
    const ok = await confirm({
      message: `确定删除域名「${row.domain}」？（软删除，可恢复）`,
      confirmText: '删除',
    })
    if (!ok) return
    try {
      const res = await api.post('/api/domains/delete', { id: row.id })
      toast.success(res.msg || '已删除')
      if (data && data.rows.length === 1 && page > 1) setPage(page - 1)
      else await reload()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '删除失败')
    }
  }

  async function doImport() {
    const text = importText.trim()
    if (!text) {
      toast.error('请输入 JSON 数据')
      return
    }
    setImporting(true)
    try {
      const res = await api.post('/api/domains/import-json', { data: text })
      const extra = res as ApiResp & ImportExtra
      const successCount = extra.success_count ?? 0
      const errorCount = extra.error_count ?? 0
      const errors = extra.errors ?? []
      toast.success(`导入完成：成功 ${successCount} 条，错误 ${errorCount} 条`)
      setImportOpen(false)
      if (errors.length) setImportErrors(errors)
      await reloadFirstPage()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '导入失败')
    } finally {
      setImporting(false)
    }
  }

  async function doBatchQuery() {
    const values = batchText
      .split(/[\n,，]+/)
      .map((s) => s.trim())
      .filter(Boolean)
    if (!values.length) {
      toast.error('请输入查询内容')
      return
    }
    setBatchLoading(true)
    try {
      const res = await api.post<BatchRow[]>('/api/domains/batch-query', {
        query_type: batchType,
        values,
      })
      const rows = res.data || []
      if (!rows.length) {
        toast.info('未查询到匹配记录')
        return
      }
      setBatchRows(rows)
      setBatchOpen(false)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '查询失败')
    } finally {
      setBatchLoading(false)
    }
  }

  async function doUnitQuery() {
    const name = unitName.trim()
    if (!name) {
      toast.error('请输入单位名称')
      return
    }
    setUnitLoading(true)
    try {
      const res = await api.get<Domain[]>('/api/domains/by-unit', { unitName: name })
      const rows = res.data || []
      if (!rows.length) {
        toast.info('未查询到匹配记录')
        return
      }
      setUnitRows(rows)
      setUnitQueried(name)
      setUnitOpen(false)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '查询失败')
    } finally {
      setUnitLoading(false)
    }
  }

  const columns: Column<Domain>[] = [
    {
      key: 'id',
      title: 'ID',
      width: 64,
      render: (d) => <span className="tnum text-slate-500">{d.id}</span>,
    },
    {
      key: 'unit_name',
      title: '主办单位',
      render: (d) => (
        <span className="block max-w-[170px] truncate font-medium text-slate-800">{d.unit_name || '-'}</span>
      ),
    },
    {
      key: 'domain',
      title: '域名',
      render: (d) => <span className="font-medium text-primary">{d.domain}</span>,
    },
    {
      key: 'main_licence',
      title: 'ICP备案号',
      render: (d) => <span className="text-slate-600">{d.main_licence || '-'}</span>,
    },
    {
      key: 'service_licence',
      title: '服务备案号',
      render: (d) => <span className="text-slate-600">{d.service_licence || '-'}</span>,
    },
    {
      key: 'nature_name',
      title: '单位性质',
      render: (d) => <span className="text-slate-600">{d.nature_name || '-'}</span>,
    },
    {
      key: 'update_record_time',
      title: '审核日期',
      width: 150,
      render: (d) => <span className="text-xs text-slate-400">{fmtTime(d.update_record_time)}</span>,
    },
    {
      key: 'actions',
      title: '操作',
      width: 100,
      render: (d) => (
        <div className="flex items-center gap-3">
          <LinkButton onClick={() => openEdit(d)}>编辑</LinkButton>
          <LinkButton danger onClick={() => remove(d)}>
            删除
          </LinkButton>
        </div>
      ),
    },
  ]

  const batchColumns: Column<BatchRow>[] = [
    {
      key: 'unit_name',
      title: '主办单位',
      render: (r) => <span className="font-medium text-slate-800">{r.unit_name || '-'}</span>,
    },
    {
      key: 'domain',
      title: '域名',
      render: (r) => <span className="text-primary">{r.domain}</span>,
    },
  ]

  const unitColumns: Column<Domain>[] = [
    {
      key: 'unit_name',
      title: '主办单位',
      render: (d) => (
        <span className="block max-w-[180px] truncate font-medium text-slate-800">{d.unit_name || '-'}</span>
      ),
    },
    {
      key: 'domain',
      title: '域名',
      render: (d) => <span className="font-medium text-primary">{d.domain}</span>,
    },
    {
      key: 'main_licence',
      title: 'ICP备案号',
      render: (d) => <span className="text-slate-600">{d.main_licence || '-'}</span>,
    },
    {
      key: 'service_licence',
      title: '服务备案号',
      render: (d) => <span className="text-slate-600">{d.service_licence || '-'}</span>,
    },
    {
      key: 'nature_name',
      title: '单位性质',
      render: (d) => <span className="text-slate-600">{d.nature_name || '-'}</span>,
    },
    {
      key: 'update_record_time',
      title: '审核日期',
      width: 150,
      render: (d) => <span className="text-xs text-slate-400">{fmtTime(d.update_record_time)}</span>,
    },
  ]

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <div className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-3">
          <Input
            value={unitKeyword}
            onChange={(e) => setUnitKeyword(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') search()
            }}
            placeholder="主办单位..."
            className="w-[180px]"
          />
          <Input
            value={domainKeyword}
            onChange={(e) => setDomainKeyword(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') search()
            }}
            placeholder="域名关键字..."
            className="w-[180px]"
          />
          <Button variant="primary" icon={<Search size={14} />} onClick={search}>
            搜索
          </Button>
          <span className="flex-1" />
          <Button variant="ghost" size="sm" icon={<Upload size={14} />} onClick={() => setImportOpen(true)}>
            ICP JSON 导入
          </Button>
          <Button variant="ghost" size="sm" icon={<ListFilter size={14} />} onClick={() => setBatchOpen(true)}>
            批量查询
          </Button>
          <Button variant="ghost" size="sm" icon={<Building2 size={14} />} onClick={() => setUnitOpen(true)}>
            按单位查域名
          </Button>
          <Button variant="primary" size="sm" icon={<Plus size={14} />} onClick={openAdd}>
            新增域名
          </Button>
        </div>

        <DataTable
          columns={columns}
          rows={data?.rows || []}
          rowKey={(d) => d.id}
          loading={loading}
          empty={
            error ? (
              <ErrorBlock message={error} onRetry={() => void reload()} />
            ) : (
              <EmptyState
                title="暂无域名资产"
                description="可通过「ICP JSON 导入」或「+ 新增域名」录入"
                action={
                  <Button size="sm" variant="primary" onClick={openAdd}>
                    新增域名
                  </Button>
                }
              />
            )
          }
        />

        {error && (data?.rows.length || 0) > 0 ? (
          <p className="px-4 pb-2 text-xs text-red-600">{error}</p>
        ) : null}

        <div className="border-t border-line px-4 py-3">
          <Pagination page={page} total={data?.total || 0} limit={LIMIT} onChange={setPage} />
        </div>
      </Card>

      {/* 新增 / 编辑域名 */}
      <Modal
        open={formOpen}
        onClose={() => setFormOpen(false)}
        title={editingId ? '编辑域名' : '新增域名'}
        footer={
          <>
            <Button onClick={() => setFormOpen(false)}>取消</Button>
            <Button variant="primary" loading={saving} onClick={save}>
              保存
            </Button>
          </>
        }
      >
        <div className="grid gap-3.5 sm:grid-cols-2">
          <Field label="主办单位">
            <Input
              value={form.unit_name}
              onChange={(e) => setForm({ ...form, unit_name: e.target.value })}
              placeholder="单位名称"
            />
          </Field>
          <Field label="域名" required>
            <Input
              value={form.domain}
              onChange={(e) => setForm({ ...form, domain: e.target.value })}
              placeholder="example.com"
            />
          </Field>
          <Field label="ICP备案号">
            <Input
              value={form.main_licence}
              onChange={(e) => setForm({ ...form, main_licence: e.target.value })}
            />
          </Field>
          <Field label="服务备案号">
            <Input
              value={form.service_licence}
              onChange={(e) => setForm({ ...form, service_licence: e.target.value })}
            />
          </Field>
          <Field label="单位性质">
            <Input
              value={form.nature_name}
              onChange={(e) => setForm({ ...form, nature_name: e.target.value })}
            />
          </Field>
          <Field label="前置审批项">
            <Input
              value={form.content_type_name}
              onChange={(e) => setForm({ ...form, content_type_name: e.target.value })}
            />
          </Field>
          {editingId ? (
            <Field label="审核日期" className="sm:col-span-2" hint="格式：YYYY-MM-DD HH:MM:SS">
              <Input
                value={form.update_record_time}
                onChange={(e) => setForm({ ...form, update_record_time: e.target.value })}
                placeholder="2025-01-01 00:00:00"
              />
            </Field>
          ) : null}
        </div>
      </Modal>

      {/* ICP JSON 导入 */}
      <Modal
        open={importOpen}
        onClose={() => setImportOpen(false)}
        title="ICP 域名 JSON 导入"
        size="lg"
        footer={
          <>
            <Button onClick={() => setImportOpen(false)}>取消</Button>
            <Button variant="primary" loading={importing} onClick={doImport}>
              导入
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-2.5">
          <div className="text-[13px] leading-7 text-slate-500">
            {IMPORT_HELP.map((line) => (
              <div key={line}>{line}</div>
            ))}
          </div>
          <Textarea
            rows={10}
            value={importText}
            onChange={(e) => setImportText(e.target.value)}
            placeholder="粘贴 ICP 备案查询返回的 JSON 数据包"
          />
        </div>
      </Modal>

      {/* 导入错误详情 */}
      <Modal
        open={!!importErrors}
        onClose={() => setImportErrors(null)}
        title="导入错误详情"
        size="lg"
        footer={
          <Button variant="primary" onClick={() => setImportErrors(null)}>
            关闭
          </Button>
        }
      >
        <pre className="max-h-[40vh] overflow-auto whitespace-pre-wrap break-words rounded-md border border-line bg-slate-50 p-3 text-xs leading-5 text-slate-700">
          {(importErrors || []).join('\n')}
        </pre>
      </Modal>

      {/* 批量查询 */}
      <Modal
        open={batchOpen}
        onClose={() => setBatchOpen(false)}
        title="域名 / 单位批量查询"
        footer={
          <>
            <Button onClick={() => setBatchOpen(false)}>取消</Button>
            <Button variant="primary" loading={batchLoading} onClick={doBatchQuery}>
              查询
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-3">
          <Field label="查询类型">
            <Select value={batchType} onChange={(e) => setBatchType(e.target.value as BatchType)}>
              <option value="unit">按单位名称（模糊）</option>
              <option value="domain">按域名关键字（模糊）</option>
            </Select>
          </Field>
          <Field label="查询值（逗号/换行分隔）">
            <Textarea
              rows={6}
              value={batchText}
              onChange={(e) => setBatchText(e.target.value)}
              placeholder={'example.com\ntest.com'}
            />
          </Field>
        </div>
      </Modal>

      {/* 批量查询结果 */}
      <Modal
        open={!!batchRows}
        onClose={() => setBatchRows(null)}
        title={`查询结果（${batchRows?.length || 0} 条）`}
        size="lg"
        footer={
          <Button variant="primary" onClick={() => setBatchRows(null)}>
            关闭
          </Button>
        }
      >
        <DataTable
          columns={batchColumns}
          rows={batchRows || []}
          rowKey={(_, i) => i}
          empty={<EmptyState title="未查询到匹配记录" />}
        />
      </Modal>

      {/* 按单位查域名 */}
      <Modal
        open={unitOpen}
        onClose={() => setUnitOpen(false)}
        title="按单位查域名"
        footer={
          <>
            <Button onClick={() => setUnitOpen(false)}>取消</Button>
            <Button variant="primary" loading={unitLoading} onClick={doUnitQuery}>
              查询
            </Button>
          </>
        }
      >
        <Field label="单位名称" hint="支持模糊匹配，返回该单位名下全部域名">
          <Input
            value={unitName}
            onChange={(e) => setUnitName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') void doUnitQuery()
            }}
            placeholder="单位名称..."
          />
        </Field>
      </Modal>

      {/* 按单位查询结果 */}
      <Modal
        open={!!unitRows}
        onClose={() => setUnitRows(null)}
        title={`「${unitQueried}」名下域名（${unitRows?.length || 0} 条）`}
        size="lg"
        footer={
          <Button variant="primary" onClick={() => setUnitRows(null)}>
            关闭
          </Button>
        }
      >
        <DataTable
          columns={unitColumns}
          rows={unitRows || []}
          rowKey={(d) => d.id}
          empty={<EmptyState title="未查询到匹配记录" />}
        />
      </Modal>
    </div>
  )
}
