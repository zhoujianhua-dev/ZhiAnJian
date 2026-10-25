import { useCallback, useState } from 'react'
import { Languages, Plus, Search, Sparkles } from 'lucide-react'
import { Card } from '@/components/ui/card'
import { DataTable, KV, type Column } from '@/components/ui/table'
import { SeverityBadge } from '@/components/ui/badge'
import { Button, LinkButton } from '@/components/ui/button'
import { Field, Input, Select, Textarea } from '@/components/ui/field'
import { Modal } from '@/components/ui/modal'
import { EmptyState, Pagination } from '@/components/ui/states'
import { useConfirm } from '@/components/ui/confirm'
import { useToast } from '@/components/ui/toast'
import { api } from '@/lib/api'
import { SEVERITY_LABEL, SEVERITY_ORDER, fmtTime } from '@/lib/format'
import { useQuery } from '@/lib/use-query'

interface Vulnerability {
  id: number
  name: string
  name_en?: string
  severity: string
  description?: string
  harm?: string
  suggestion?: string
  updated_at?: string
  needs_translation?: boolean
}

interface FormState {
  name: string
  severity: string
  description: string
  harm: string
  suggestion: string
}

const EMPTY_FORM: FormState = { name: '', severity: 'medium', description: '', harm: '', suggestion: '' }

const LIMIT = 10

export function Vulnerabilities() {
  const toast = useToast()
  const confirm = useConfirm()

  const [keyword, setKeyword] = useState('')
  const [committedKeyword, setCommittedKeyword] = useState('')
  const [severity, setSeverity] = useState('')
  const [page, setPage] = useState(1)

  const [formOpen, setFormOpen] = useState(false)
  const [editingId, setEditingId] = useState<number | null>(null)
  const [form, setForm] = useState<FormState>(EMPTY_FORM)
  const [saving, setSaving] = useState(false)
  const [detail, setDetail] = useState<Vulnerability | null>(null)
  const [translating, setTranslating] = useState(false)
  const [aiTranslating, setAiTranslating] = useState(false)

  const load = useCallback(async () => {
    const res = await api.get<Vulnerability[]>('/api/vulnerabilities', {
      page,
      limit: LIMIT,
      name: committedKeyword,
      severity,
    })
    return { rows: res.data || [], total: res.count || 0 }
  }, [page, committedKeyword, severity])

  const { data, loading, error, reload } = useQuery(load, [load])

  function search() {
    setPage(1)
    setCommittedKeyword(keyword.trim())
  }

  /** 一键把英文漏洞名翻译为中文（内置安全术语词典，可反复执行） */
  async function translateAll() {
    const ok = await confirm({
      message: '把漏洞库里仍是英文的名称批量翻译为中文？英文原名会保留在「原始名称」里，已是中文的条目不受影响。',
      confirmText: '开始翻译',
      danger: false,
    })
    if (!ok) return
    setTranslating(true)
    try {
      const res = await api.post<{ updated: number; skipped: number }>('/api/vulnerabilities/translate')
      toast.success(res.msg || '翻译完成')
      await reload()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '翻译失败')
    } finally {
      setTranslating(false)
    }
  }

  function openAdd() {
    setEditingId(null)
    setForm(EMPTY_FORM)
    setFormOpen(true)
  }

  async function openEdit(id: number) {
    try {
      const res = await api.get<Vulnerability>('/api/vulnerability/detail', { id })
      const v = res.data as Vulnerability
      setEditingId(id)
      setForm({
        name: v.name || '',
        severity: v.severity || 'unknown',
        description: v.description || '',
        harm: v.harm || '',
        suggestion: v.suggestion || '',
      })
      setFormOpen(true)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '读取失败')
    }
  }

  /** AI 翻译描述/危害/整改建议：传 id 翻单条，不传则批量处理仍含英文的条目 */
  async function aiTranslate(id?: number) {
    if (!id) {
      const ok = await confirm({
        message: '用 AI 把漏洞库里仍是英文的「描述 / 危害 / 整改建议」翻译成中文？每次最多处理 10 条，可重复执行。',
        confirmText: '开始翻译',
        danger: false,
      })
      if (!ok) return
    }
    setAiTranslating(true)
    try {
      const res = await api.post<{ updated: number[]; failed: Array<{ id: number; msg: string }> }>(
        '/api/vulnerabilities/ai-translate',
        id ? { id } : { limit: 10 },
      )
      toast.success(res.msg || 'AI 翻译完成')
      const failed = res.data?.failed || []
      if (failed.length) toast.warning(`有 ${failed.length} 条未翻译：${failed[0].msg}`)
      await reload()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'AI 翻译失败')
    } finally {
      setAiTranslating(false)
    }
  }

  async function save() {
    if (!form.name.trim()) {
      toast.error('请输入漏洞名称')
      return
    }
    setSaving(true)
    try {
      const payload = { ...form, name: form.name.trim() }
      const res = editingId
        ? await api.post('/api/vulnerability/update', { id: editingId, ...payload })
        : await api.post('/api/vulnerability/add', payload)
      toast.success(res.msg || '保存成功')
      setFormOpen(false)
      await reload()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '保存失败')
    } finally {
      setSaving(false)
    }
  }

  async function remove(v: Vulnerability) {
    const ok = await confirm({
      message: `确定删除漏洞「${v.name}」？删除后不可恢复。`,
      confirmText: '删除',
    })
    if (!ok) return
    try {
      const res = await api.post('/api/vulnerability/delete', { id: v.id })
      toast.success(res.msg || '已删除')
      if (data && data.rows.length === 1 && page > 1) setPage(page - 1)
      else await reload()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '删除失败')
    }
  }

  const columns: Column<Vulnerability>[] = [
    { key: 'id', title: 'ID', width: 64, render: (v) => <span className="tnum text-slate-500">{v.id}</span> },
    {
      key: 'name',
      title: '漏洞名称',
      render: (v) => (
        <div className="min-w-0">
          <span className="block font-medium text-slate-800">{v.name}</span>
          {v.name_en ? (
            <span className="mt-0.5 block max-w-[360px] truncate text-[11.5px] text-slate-400" title={v.name_en}>
              {v.name_en}
            </span>
          ) : null}
        </div>
      ),
    },
    { key: 'severity', title: '等级', width: 76, render: (v) => <SeverityBadge severity={v.severity} /> },
    {
      key: 'description',
      title: '漏洞描述',
      render: (v) => (
        <span className="block max-w-[380px] truncate text-slate-500">{v.description || '-'}</span>
      ),
    },
    {
      key: 'updated_at',
      title: '更新时间',
      width: 150,
      render: (v) => <span className="text-xs text-slate-400">{fmtTime(v.updated_at)}</span>,
    },
    {
      key: 'actions',
      title: '操作',
      width: 170,
      render: (v) => (
        <div className="flex items-center gap-3 whitespace-nowrap">
          {v.needs_translation ? (
            <LinkButton disabled={aiTranslating} onClick={() => void aiTranslate(v.id)}>
              AI 翻译
            </LinkButton>
          ) : null}
          <LinkButton onClick={() => setDetail(v)}>详情</LinkButton>
          <LinkButton onClick={() => openEdit(v.id)}>编辑</LinkButton>
          <LinkButton danger onClick={() => remove(v)}>
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
            value={keyword}
            onChange={(e) => setKeyword(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') search()
            }}
            placeholder="按漏洞名称搜索…"
            className="w-[220px]"
          />
          <Select value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1) }} className="w-[130px]">
            <option value="">全部等级</option>
            {SEVERITY_ORDER.map((s) => (
              <option key={s} value={s}>
                {SEVERITY_LABEL[s]}
              </option>
            ))}
          </Select>
          <Button variant="primary" icon={<Search size={14} />} onClick={search}>
            搜索
          </Button>
          <span className="flex-1" />
          <Button
            variant="ghost"
            size="sm"
            icon={<Languages size={14} />}
            loading={translating}
            title="用内置术语词典把英文漏洞名称翻译成中文（不调用 AI）"
            onClick={() => void translateAll()}
          >
            翻译名称
          </Button>
          <Button
            variant="ghost"
            size="sm"
            icon={<Sparkles size={14} />}
            loading={aiTranslating}
            title="用 AI 把英文的描述/危害/整改建议翻译成中文"
            onClick={() => void aiTranslate()}
          >
            AI 翻译描述
          </Button>
          <Button variant="primary" size="sm" icon={<Plus size={14} />} onClick={openAdd}>
            新增漏洞
          </Button>
        </div>

        <DataTable
          columns={columns}
          rows={data?.rows || []}
          rowKey={(v) => v.id}
          loading={loading}
          empty={
            <EmptyState
              title="暂无漏洞数据"
              description="维护漏洞知识库，新建报告时可快速引用"
              action={
                <Button size="sm" variant="primary" onClick={openAdd}>
                  新增漏洞
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

      <Modal
        open={formOpen}
        onClose={() => setFormOpen(false)}
        title={editingId ? '编辑漏洞' : '新增漏洞'}
        size="lg"
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
          <Field label="漏洞名称" required hint="输入英文会自动翻译为中文，英文原名保留在「原始名称」">
            <Input
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="如：SQL 注入漏洞 / Authentication Bypass"
            />
          </Field>
          <Field label="漏洞等级">
            <Select value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>
              {SEVERITY_ORDER.map((s) => (
                <option key={s} value={s}>
                  {SEVERITY_LABEL[s]}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="漏洞描述" className="sm:col-span-2">
            <Textarea
              rows={3}
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
            />
          </Field>
          <Field label="漏洞危害" className="sm:col-span-2">
            <Textarea rows={3} value={form.harm} onChange={(e) => setForm({ ...form, harm: e.target.value })} />
          </Field>
          <Field label="整改建议" className="sm:col-span-2">
            <Textarea
              rows={3}
              value={form.suggestion}
              onChange={(e) => setForm({ ...form, suggestion: e.target.value })}
            />
          </Field>
        </div>
      </Modal>

      <Modal
        open={!!detail}
        onClose={() => setDetail(null)}
        title="漏洞详情"
        size="lg"
        footer={
          <Button variant="primary" onClick={() => setDetail(null)}>
            关闭
          </Button>
        }
      >
        {detail ? (
          <div>
            <KV label="漏洞名称">{detail.name}</KV>
            {detail.name_en ? <KV label="原始名称">{detail.name_en}</KV> : null}
            <KV label="漏洞等级">
              <SeverityBadge severity={detail.severity} />
            </KV>
            <KV label="漏洞描述">{detail.description || '-'}</KV>
            <KV label="漏洞危害">{detail.harm || '-'}</KV>
            <KV label="整改建议">{detail.suggestion || '-'}</KV>
          </div>
        ) : null}
      </Modal>
    </div>
  )
}
