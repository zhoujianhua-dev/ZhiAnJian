import { useCallback, useState } from 'react'
import { Link2, Plus, Search } from 'lucide-react'
import { Card } from '@/components/ui/card'
import { DataTable, type Column } from '@/components/ui/table'
import { Badge, TagChip } from '@/components/ui/badge'
import { Button, LinkButton } from '@/components/ui/button'
import { Field, Input, Select, Textarea } from '@/components/ui/field'
import { Modal } from '@/components/ui/modal'
import { EmptyState, Pagination } from '@/components/ui/states'
import { useConfirm } from '@/components/ui/confirm'
import { useToast } from '@/components/ui/toast'
import { api } from '@/lib/api'
import { fmtTime } from '@/lib/format'
import { useQuery } from '@/lib/use-query'

const LIMIT = 10

interface Tag {
  id: number
  name: string
  description?: string
  /** 关联单位名称，后端以换行拼接 */
  unit?: string
  unit_count?: number
  created_at?: string
}

interface TagOption {
  id: number
  name: string
}

interface TagForm {
  name: string
  description: string
  unit: string
}

const EMPTY_FORM: TagForm = { name: '', description: '', unit: '' }

/** 把后端换行拼接的单位串拆成名称数组 */
function unitList(raw?: string) {
  return (raw || '')
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean)
}

export function Tags() {
  const toast = useToast()
  const confirm = useConfirm()

  const [keyword, setKeyword] = useState('')
  const [committedKeyword, setCommittedKeyword] = useState('')
  const [page, setPage] = useState(1)

  const load = useCallback(async () => {
    const res = await api.get<Tag[]>('/api/tags', {
      page,
      limit: LIMIT,
      keyword: committedKeyword,
    })
    return { rows: res.data || [], total: res.count || 0 }
  }, [page, committedKeyword])

  const { data, loading, error, reload } = useQuery(load, [load])
  const rows = data?.rows || []

  function goFirstPage() {
    if (page === 1) void reload()
    else setPage(1)
  }

  function search() {
    const kw = keyword.trim()
    if (page === 1 && kw === committedKeyword) {
      void reload()
      return
    }
    setPage(1)
    setCommittedKeyword(kw)
  }

  // ---------------- 新建 / 编辑 ----------------
  const [formOpen, setFormOpen] = useState(false)
  const [editingId, setEditingId] = useState<number | null>(null)
  const [form, setForm] = useState<TagForm>(EMPTY_FORM)
  const [saving, setSaving] = useState(false)

  function openAdd() {
    setEditingId(null)
    setForm(EMPTY_FORM)
    setFormOpen(true)
  }

  async function openEdit(id: number) {
    try {
      const res = await api.get<Tag>('/api/tags/detail', { id })
      const t = res.data
      if (!t) {
        toast.error('标签不存在')
        return
      }
      setEditingId(id)
      setForm({
        name: t.name || '',
        description: t.description || '',
        unit: t.unit || '',
      })
      setFormOpen(true)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '读取失败')
    }
  }

  async function save() {
    const name = form.name.trim()
    if (!name) {
      toast.error('请输入标签名称')
      return
    }
    setSaving(true)
    try {
      if (editingId === null) {
        const res = await api.post('/api/tags/add', {
          name,
          description: form.description,
          unit: form.unit,
        })
        toast.success(res.msg || '添加成功')
        setFormOpen(false)
        goFirstPage()
      } else {
        const res = await api.post('/api/tags/update', {
          id: editingId,
          name,
          description: form.description,
          unit: form.unit,
        })
        toast.success(res.msg || '更新成功')
        setFormOpen(false)
        await reload()
      }
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '保存失败')
    } finally {
      setSaving(false)
    }
  }

  // ---------------- 删除 ----------------
  async function remove(t: Tag) {
    const ok = await confirm({
      message: `确定删除标签「${t.name}」？关联关系将一并解除。`,
      confirmText: '删除',
    })
    if (!ok) return
    try {
      const res = await api.post('/api/tags/delete', { id: t.id })
      toast.success(res.msg || '已删除')
      if (rows.length === 1 && page > 1) setPage(page - 1)
      else await reload()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '删除失败')
    }
  }

  // ---------------- 关联单位到标签 ----------------
  const [assignOpen, setAssignOpen] = useState(false)
  const [assignOptions, setAssignOptions] = useState<TagOption[]>([])
  const [assignTagId, setAssignTagId] = useState('')
  const [assignUnit, setAssignUnit] = useState('')
  const [assigning, setAssigning] = useState(false)

  async function openAssign() {
    try {
      const res = await api.get<TagOption[]>('/api/tags/options')
      const list = res.data || []
      if (!list.length) {
        toast.error('请先新建至少一个标签')
        return
      }
      setAssignOptions(list)
      setAssignTagId(String(list[0].id))
      setAssignUnit('')
      setAssignOpen(true)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '读取标签失败')
    }
  }

  async function doAssign() {
    if (!assignUnit.trim()) {
      toast.error('请输入至少一个单位名称')
      return
    }
    setAssigning(true)
    try {
      const res = await api.post('/api/tags/assign', { tag_id: assignTagId, unit: assignUnit })
      const created = Number(res.success_count)
      const existing = Number(res.existing_count)
      toast.success(
        `关联成功：新建单位 ${Number.isFinite(created) ? created : 0} 个，已存在 ${
          Number.isFinite(existing) ? existing : 0
        } 个`,
      )
      setAssignOpen(false)
      await reload()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '关联失败')
    } finally {
      setAssigning(false)
    }
  }

  const columns: Column<Tag>[] = [
    { key: 'id', title: 'ID', width: 64, render: (t) => <span className="tnum text-slate-500">{t.id}</span> },
    {
      key: 'name',
      title: '标签名称',
      render: (t) => <span className="font-semibold text-primary">{t.name}</span>,
    },
    {
      key: 'description',
      title: '描述',
      className: 'max-w-[200px]',
      render: (t) => (
        <span className="block max-w-[200px] truncate text-slate-500" title={t.description || ''}>
          {t.description || '-'}
        </span>
      ),
    },
    {
      key: 'unit',
      title: '关联单位',
      className: 'max-w-[260px]',
      render: (t) => {
        const units = unitList(t.unit)
        if (!units.length) return <span className="text-slate-400">-</span>
        return (
          <div className="flex max-w-[260px] flex-wrap gap-1">
            {units.map((u) => (
              <TagChip key={u}>{u}</TagChip>
            ))}
          </div>
        )
      },
    },
    {
      key: 'unit_count',
      title: '单位数',
      width: 80,
      render: (t) => <Badge tone="blue">{t.unit_count ?? 0}</Badge>,
    },
    {
      key: 'created_at',
      title: '创建时间',
      width: 150,
      render: (t) => <span className="text-xs text-slate-400">{fmtTime(t.created_at)}</span>,
    },
    {
      key: 'actions',
      title: '操作',
      width: 100,
      render: (t) => (
        <div className="flex items-center gap-3">
          <LinkButton onClick={() => openEdit(t.id)}>编辑</LinkButton>
          <LinkButton danger onClick={() => remove(t)}>
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
            placeholder="按标签名搜索..."
            className="w-[200px]"
          />
          <Button variant="primary" icon={<Search size={14} />} onClick={search}>
            搜索
          </Button>
          <span className="flex-1" />
          <Button variant="ghost" size="sm" icon={<Link2 size={13} />} onClick={openAssign}>
            关联单位到标签
          </Button>
          <Button variant="primary" size="sm" icon={<Plus size={13} />} onClick={openAdd}>
            新建标签
          </Button>
        </div>

        <DataTable
          columns={columns}
          rows={rows}
          rowKey={(t) => t.id}
          loading={loading}
          empty={
            <EmptyState
              title="暂无标签"
              description="新建标签并关联单位，便于批量管理资产"
              action={
                <Button size="sm" variant="primary" onClick={openAdd}>
                  新建标签
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

      {/* 新建 / 编辑标签 */}
      <Modal
        open={formOpen}
        onClose={() => setFormOpen(false)}
        title={editingId === null ? '新建标签' : '编辑标签'}
        size="md"
        footer={
          <>
            <Button onClick={() => setFormOpen(false)}>取消</Button>
            <Button variant="primary" loading={saving} onClick={save}>
              {editingId === null ? '创建' : '保存'}
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-3">
          <Field label="标签名称" required>
            <Input
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="如：重点监管单位"
            />
          </Field>
          <Field label="描述">
            <Textarea
              rows={2}
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
            />
          </Field>
          <Field label={editingId === null ? '关联单位（每行一个单位名称）' : '关联单位（每行一个）'}>
            <Textarea
              rows={editingId === null ? 6 : 8}
              value={form.unit}
              onChange={(e) => setForm({ ...form, unit: e.target.value })}
              placeholder="每行一个单位名称"
            />
          </Field>
        </div>
      </Modal>

      {/* 关联单位到标签 */}
      <Modal
        open={assignOpen}
        onClose={() => setAssignOpen(false)}
        title="关联单位到标签"
        size="md"
        footer={
          <>
            <Button onClick={() => setAssignOpen(false)}>取消</Button>
            <Button variant="primary" loading={assigning} onClick={doAssign}>
              关联
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-3">
          <Field label="选择标签" required>
            <Select value={assignTagId} onChange={(e) => setAssignTagId(e.target.value)}>
              {assignOptions.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="要关联的单位（每行一个；不存在的单位会自动新建，已有关联不会被清除）">
            <Textarea
              rows={8}
              value={assignUnit}
              onChange={(e) => setAssignUnit(e.target.value)}
              placeholder="每行一个单位名称"
            />
          </Field>
        </div>
      </Modal>
    </div>
  )
}
