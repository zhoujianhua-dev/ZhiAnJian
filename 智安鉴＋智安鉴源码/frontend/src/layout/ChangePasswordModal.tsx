import { useState } from 'react'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Field, Input } from '@/components/ui/field'
import { Modal } from '@/components/ui/modal'
import { useToast } from '@/components/ui/toast'
import { useAuth } from '@/store/auth'

export function ChangePasswordModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const toast = useToast()
  const { refresh } = useAuth()
  const [oldPwd, setOldPwd] = useState('')
  const [newPwd, setNewPwd] = useState('')
  const [confirmPwd, setConfirmPwd] = useState('')
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)

  function reset() {
    setOldPwd('')
    setNewPwd('')
    setConfirmPwd('')
    setError('')
  }

  async function submit() {
    setError('')
    if (!oldPwd || !newPwd) {
      setError('请填写原密码与新密码')
      return
    }
    if (newPwd !== confirmPwd) {
      setError('两次输入的新密码不一致')
      return
    }
    setSaving(true)
    try {
      const res = await api.post('/api/auth/password', { old_password: oldPwd, new_password: newPwd })
      toast.success(res.msg || '密码已修改')
      await refresh()
      reset()
      onClose()
    } catch (e) {
      setError(e instanceof Error ? e.message : '修改失败')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal
      open={open}
      onClose={() => {
        reset()
        onClose()
      }}
      title="修改密码"
      size="sm"
      footer={
        <>
          <Button
            onClick={() => {
              reset()
              onClose()
            }}
          >
            取消
          </Button>
          <Button variant="primary" loading={saving} onClick={submit}>
            保存
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        <Field label="原密码" required>
          <Input
            type="password"
            autoComplete="current-password"
            value={oldPwd}
            onChange={(e) => setOldPwd(e.target.value)}
          />
        </Field>
        <Field label="新密码" required hint="至少 6 位">
          <Input
            type="password"
            autoComplete="new-password"
            value={newPwd}
            onChange={(e) => setNewPwd(e.target.value)}
          />
        </Field>
        <Field label="确认新密码" required error={error}>
          <Input
            type="password"
            autoComplete="new-password"
            value={confirmPwd}
            onChange={(e) => setConfirmPwd(e.target.value)}
          />
        </Field>
      </div>
    </Modal>
  )
}
