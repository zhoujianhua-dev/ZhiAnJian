import { useCallback, useState } from 'react'
import { Plus, Search } from 'lucide-react'
import { Card, CardBody, CardHeader } from '@/components/ui/card'
import { DataTable, type Column } from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Button, LinkButton } from '@/components/ui/button'
import { Field, Input, Select } from '@/components/ui/field'
import { Modal } from '@/components/ui/modal'
import { EmptyState, ErrorBlock } from '@/components/ui/states'
import { useConfirm } from '@/components/ui/confirm'
import { useToast } from '@/components/ui/toast'
import { api } from '@/lib/api'
import { fmtTime } from '@/lib/format'
import { useQuery } from '@/lib/use-query'
import { useAuth } from '@/store/auth'

/** 与后端 core/auth.py 的校验规则保持一致 */
const USERNAME_RE = /^[A-Za-z0-9_.-]{3,32}$/
const MIN_PASSWORD_LEN = 6

const ROLE_OPTIONS = [
  { value: 'user', label: '普通用户' },
  { value: 'admin', label: '管理员' },
] as const

function validateUsername(name: string): string | null {
  if (!USERNAME_RE.test(name)) return '用户名需为 3-32 位字母、数字、下划线、点或短横线'
  return null
}

function validatePassword(pwd: string): string | null {
  if (pwd.length < MIN_PASSWORD_LEN) return `密码至少 ${MIN_PASSWORD_LEN} 位`
  return null
}

interface UserRow {
  id: number
  username: string
  display_name?: string
  role: string
  role_cn?: string
  is_active: number
  remark?: string
  created_at?: string
  updated_at?: string
  last_login_at?: string
}

interface AddForm {
  username: string
  password: string
  display_name: string
  role: string
  remark: string
}

const EMPTY_ADD: AddForm = { username: '', password: '', display_name: '', role: 'user', remark: '' }

interface EditForm {
  display_name: string
  role: string
  is_active: number
  remark: string
}

export function Users() {
  const toast = useToast()
  const confirm = useConfirm()
  const { user: me } = useAuth()

  const [keyword, setKeyword] = useState('')
  const [committedKeyword, setCommittedKeyword] = useState('')

  const [addOpen, setAddOpen] = useState(false)
  const [addForm, setAddForm] = useState<AddForm>(EMPTY_ADD)
  const [addErrors, setAddErrors] = useState<{ username?: string; password?: string }>({})

  const [editing, setEditing] = useState<UserRow | null>(null)
  const [editForm, setEditForm] = useState<EditForm>({ display_name: '', role: 'user', is_active: 1, remark: '' })

  const [resetUser, setResetUser] = useState<UserRow | null>(null)
  const [resetPwd, setResetPwd] = useState('')
  const [resetError, setResetError] = useState('')

  const [saving, setSaving] = useState(false)

  const load = useCallback(async () => {
    const res = await api.get<UserRow[]>('/api/users', { keyword: committedKeyword })
    return { rows: res.data || [], total: res.count || 0 }
  }, [committedKeyword])

  const { data, loading, error, reload } = useQuery(load, [load])

  function search() {
    setCommittedKeyword(keyword.trim())
  }

  function isSelf(u: UserRow) {
    return !!me && u.id === me.id
  }

  function openAdd() {
    setAddForm(EMPTY_ADD)
    setAddErrors({})
    setAddOpen(true)
  }

  async function doAdd() {
    const username = addForm.username.trim()
    const errors = {
      username: validateUsername(username) || undefined,
      password: validatePassword(addForm.password) || undefined,
    }
    setAddErrors(errors)
    if (errors.username || errors.password) return
    setSaving(true)
    try {
      const res = await api.post('/api/users/add', {
        username,
        password: addForm.password,
        display_name: addForm.display_name.trim(),
        role: addForm.role,
        remark: addForm.remark.trim(),
      })
      toast.success(res.msg || '已新增账号')
      setAddOpen(false)
      await reload()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '创建失败')
    } finally {
      setSaving(false)
    }
  }

  function openEdit(u: UserRow) {
    setEditing(u)
    setEditForm({
      display_name: u.display_name || '',
      role: u.role,
      is_active: u.is_active ? 1 : 0,
      remark: u.remark || '',
    })
  }

  async function doEdit() {
    if (!editing) return
    setSaving(true)
    try {
      const res = await api.post('/api/users/update', {
        id: editing.id,
        display_name: editForm.display_name.trim(),
        role: editForm.role,
        is_active: Number(editForm.is_active),
        remark: editForm.remark.trim(),
      })
      toast.success(res.msg || '已保存')
      setEditing(null)
      await reload()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '保存失败')
    } finally {
      setSaving(false)
    }
  }

  function openReset(u: UserRow) {
    setResetUser(u)
    setResetPwd('')
    setResetError('')
  }

  async function doReset() {
    if (!resetUser) return
    const err = resetPwd ? validatePassword(resetPwd) : '请输入新密码'
    setResetError(err || '')
    if (err) return
    setSaving(true)
    try {
      const res = await api.post('/api/users/update', { id: resetUser.id, password: resetPwd })
      toast.success(res.msg || '密码已重置')
      setResetUser(null)
      await reload()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '重置失败')
    } finally {
      setSaving(false)
    }
  }

  async function toggleActive(u: UserRow) {
    const next = u.is_active ? 0 : 1
    if (!next) {
      const ok = await confirm({
        message: `停用后「${u.username}」将立即无法登录，确定停用？`,
        confirmText: '停用',
      })
      if (!ok) return
    }
    try {
      const res = await api.post('/api/users/update', { id: u.id, is_active: next })
      toast.success(res.msg || (next ? '已启用' : '已停用'))
      await reload()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '操作失败')
    }
  }

  async function removeUser(u: UserRow) {
    const ok = await confirm({
      message: `确定删除账号「${u.username}」？删除后该账号立即失效且不可恢复。`,
      confirmText: '删除',
    })
    if (!ok) return
    try {
      const res = await api.post('/api/users/delete', { id: u.id })
      toast.success(res.msg || '已删除')
      await reload()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '删除失败')
    }
  }

  const columns: Column<UserRow>[] = [
    {
      key: 'username',
      title: '用户名',
      render: (u) => (
        <span className="inline-flex items-center gap-2">
          <span className="font-semibold text-slate-800">{u.username}</span>
          {isSelf(u) ? <Badge tone="sky">当前登录</Badge> : null}
        </span>
      ),
    },
    {
      key: 'display_name',
      title: '姓名',
      render: (u) => <span className="text-slate-700">{u.display_name || '-'}</span>,
    },
    {
      key: 'role',
      title: '角色',
      width: 96,
      render: (u) =>
        u.role === 'admin' ? <Badge tone="blue">管理员</Badge> : <Badge tone="slate">普通用户</Badge>,
    },
    {
      key: 'is_active',
      title: '状态',
      width: 88,
      render: (u) => (u.is_active ? <Badge tone="green">启用</Badge> : <Badge tone="slate">已停用</Badge>),
    },
    {
      key: 'last_login_at',
      title: '最近登录',
      width: 150,
      render: (u) => (
        <span className="text-xs text-slate-400">{u.last_login_at ? fmtTime(u.last_login_at) : '从未登录'}</span>
      ),
    },
    {
      key: 'created_at',
      title: '创建时间',
      width: 150,
      render: (u) => <span className="text-xs text-slate-400">{fmtTime(u.created_at)}</span>,
    },
    {
      key: 'remark',
      title: '备注',
      render: (u) => (
        <span className="block max-w-[180px] truncate text-xs text-slate-500">{u.remark || '-'}</span>
      ),
    },
    {
      key: 'actions',
      title: '操作',
      width: 230,
      render: (u) => (
        <div className="flex items-center gap-3">
          <LinkButton onClick={() => openEdit(u)}>编辑</LinkButton>
          <LinkButton onClick={() => openReset(u)}>重置密码</LinkButton>
          {isSelf(u) ? null : (
            <LinkButton onClick={() => toggleActive(u)}>{u.is_active ? '停用' : '启用'}</LinkButton>
          )}
          {isSelf(u) ? null : (
            <LinkButton danger onClick={() => removeUser(u)}>
              删除
            </LinkButton>
          )}
        </div>
      ),
    },
  ]

  const editSelf = !!editing && !!me && editing.id === me.id

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
            placeholder="按用户名或姓名搜索..."
            className="w-[220px]"
          />
          <Button variant="primary" icon={<Search size={14} />} onClick={search}>
            搜索
          </Button>
          <span className="flex-1" />
          <span className="text-xs text-slate-400">{data ? `共 ${data.total} 个账号` : ''}</span>
          <Button variant="primary" size="sm" icon={<Plus size={14} />} onClick={openAdd}>
            新建用户
          </Button>
        </div>

        <DataTable
          columns={columns}
          rows={data?.rows || []}
          rowKey={(u) => u.id}
          loading={loading}
          empty={
            error ? (
              <ErrorBlock message={error} onRetry={() => void reload()} />
            ) : (
              <EmptyState
                title="没有匹配的账号"
                description="换个关键词，或点击右上角新建用户"
                action={
                  <Button size="sm" variant="primary" onClick={openAdd}>
                    新建用户
                  </Button>
                }
              />
            )
          }
        />

        {error && (data?.rows.length || 0) > 0 ? (
          <p className="px-4 pb-2 text-xs text-red-600">{error}</p>
        ) : null}
      </Card>

      <Card>
        <CardHeader title="角色说明" />
        <CardBody className="flex flex-col gap-2 text-[13px] leading-6 text-slate-600">
          <div className="flex items-start gap-2">
            <Badge tone="blue" className="mt-[3px]">
              管理员
            </Badge>
            <span className="min-w-0 flex-1">全部业务功能，并可进入「用户管理」新建/停用账号、重置密码</span>
          </div>
          <div className="flex items-start gap-2">
            <Badge tone="slate" className="mt-[3px]">
              普通用户
            </Badge>
            <span className="min-w-0 flex-1">
              全部业务功能（仪表盘、资产、漏洞、报告、AI、扫描、工具），无用户管理入口
            </span>
          </div>
          <p className="text-xs leading-6 text-slate-500">
            密码以 PBKDF2 加盐哈希存储，忘记密码只能由管理员重置；系统始终至少保留一名启用的管理员。
          </p>
        </CardBody>
      </Card>

      {/* 新建用户 */}
      <Modal
        open={addOpen}
        onClose={() => setAddOpen(false)}
        title="新建用户"
        footer={
          <>
            <Button onClick={() => setAddOpen(false)}>取消</Button>
            <Button variant="primary" loading={saving} onClick={doAdd}>
              创建
            </Button>
          </>
        }
      >
        <div className="grid gap-3.5 sm:grid-cols-2">
          <Field label="用户名" required error={addErrors.username}>
            <Input
              value={addForm.username}
              onChange={(e) => setAddForm({ ...addForm, username: e.target.value })}
              placeholder="3-32 位字母、数字、_ . -"
            />
          </Field>
          <Field label="姓名">
            <Input
              value={addForm.display_name}
              onChange={(e) => setAddForm({ ...addForm, display_name: e.target.value })}
              placeholder="留空则同用户名"
            />
          </Field>
          <Field label="初始密码" required error={addErrors.password}>
            <Input
              type="password"
              autoComplete="new-password"
              value={addForm.password}
              onChange={(e) => setAddForm({ ...addForm, password: e.target.value })}
              placeholder="至少 6 位"
            />
          </Field>
          <Field label="角色">
            <Select value={addForm.role} onChange={(e) => setAddForm({ ...addForm, role: e.target.value })}>
              {ROLE_OPTIONS.map((r) => (
                <option key={r.value} value={r.value}>
                  {r.label}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="备注" className="sm:col-span-2">
            <Input
              value={addForm.remark}
              onChange={(e) => setAddForm({ ...addForm, remark: e.target.value })}
              placeholder="如：所属部门 / 用途"
            />
          </Field>
        </div>
      </Modal>

      {/* 编辑用户 */}
      <Modal
        open={!!editing}
        onClose={() => setEditing(null)}
        title={`编辑用户 · ${editing?.username || ''}`}
        footer={
          <>
            <Button onClick={() => setEditing(null)}>取消</Button>
            <Button variant="primary" loading={saving} onClick={doEdit}>
              保存
            </Button>
          </>
        }
      >
        <div className="grid gap-3.5 sm:grid-cols-2">
          <Field label="用户名">
            <Input value={editing?.username || ''} disabled />
          </Field>
          <Field label="姓名">
            <Input
              value={editForm.display_name}
              onChange={(e) => setEditForm({ ...editForm, display_name: e.target.value })}
            />
          </Field>
          <Field label="角色">
            <Select
              value={editForm.role}
              disabled={editSelf}
              onChange={(e) => setEditForm({ ...editForm, role: e.target.value })}
            >
              {ROLE_OPTIONS.map((r) => (
                <option key={r.value} value={r.value}>
                  {r.label}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="状态">
            <Select
              value={String(editForm.is_active)}
              disabled={editSelf}
              onChange={(e) => setEditForm({ ...editForm, is_active: Number(e.target.value) })}
            >
              <option value="1">启用</option>
              <option value="0">停用</option>
            </Select>
          </Field>
          <Field label="备注" className="sm:col-span-2">
            <Input
              value={editForm.remark}
              onChange={(e) => setEditForm({ ...editForm, remark: e.target.value })}
            />
          </Field>
        </div>
        {editSelf ? (
          <p className="mt-2.5 text-xs text-slate-400">当前登录账号不能修改自己的角色与状态</p>
        ) : null}
      </Modal>

      {/* 重置密码 */}
      <Modal
        open={!!resetUser}
        onClose={() => setResetUser(null)}
        title={`重置密码 · ${resetUser?.username || ''}`}
        size="sm"
        footer={
          <>
            <Button onClick={() => setResetUser(null)}>取消</Button>
            <Button variant="primary" loading={saving} onClick={doReset}>
              确认重置
            </Button>
          </>
        }
      >
        <Field label="新密码" required error={resetError}>
          <Input
            type="password"
            autoComplete="new-password"
            value={resetPwd}
            onChange={(e) => {
              setResetPwd(e.target.value)
              setResetError('')
            }}
            placeholder="至少 6 位"
          />
        </Field>
        <p className="mt-2.5 text-xs text-slate-400">重置后请把新密码告知本人，并提醒其尽快自行修改。</p>
      </Modal>
    </div>
  )
}
