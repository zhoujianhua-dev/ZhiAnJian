import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Eye, EyeOff, ShieldCheck } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Field, Input } from '@/components/ui/field'
import { useAuth } from '@/store/auth'

export function Login() {
  const { boot, user, loading, login } = useAuth()
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPwd, setShowPwd] = useState(false)
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const next = params.get('next')
  const target = next && next.startsWith('/') ? next : '/'

  useEffect(() => {
    if (!loading && user) navigate(target, { replace: true })
  }, [loading, user, navigate, target])

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    if (!username.trim() || !password) {
      setError('请输入用户名和密码')
      return
    }
    setSubmitting(true)
    try {
      await login(username.trim(), password)
      navigate(target, { replace: true })
    } catch (err) {
      const status = (err as { status?: number }).status
      if (status && status >= 500) setError(`服务器内部错误（${status}），请查看服务端日志`)
      else if (status && status !== 401) setError(err instanceof Error ? err.message : '登录失败')
      else setError(err instanceof Error ? err.message : '用户名或密码错误')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-canvas px-4">
      <div className="w-full max-w-[380px]">
        <div className="mb-5 flex items-center gap-3">
          <span className="flex h-10 w-10 items-center justify-center rounded-md bg-primary text-white">
            <ShieldCheck size={22} />
          </span>
          <div className="min-w-0">
            <div className="text-[16px] font-semibold leading-tight text-slate-900">
              {boot?.app_name || '智安鉴'}
            </div>
            <div className="truncate text-xs text-slate-500">
              {boot?.app_title || '智能安全检测与漏洞报告系统'}
            </div>
          </div>
        </div>

        <form
          onSubmit={submit}
          className="rounded-lg border border-line bg-surface p-6 shadow-card"
        >
          <h1 className="mb-4 text-[15px] font-semibold text-slate-900">登录</h1>

          <div className="flex flex-col gap-3">
            <Field label="用户名">
              <Input
                autoFocus
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="请输入用户名"
              />
            </Field>

            <Field label="密码">
              <div className="relative">
                <Input
                  type={showPwd ? 'text' : 'password'}
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="请输入密码"
                  className="pr-10"
                />
                <button
                  type="button"
                  onClick={() => setShowPwd((v) => !v)}
                  className="absolute right-1.5 top-1/2 -translate-y-1/2 rounded p-1.5 text-slate-400 hover:bg-slate-100 hover:text-slate-600"
                  aria-label={showPwd ? '隐藏密码' : '显示密码'}
                >
                  {showPwd ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
            </Field>
          </div>

          <p className="mt-2 min-h-[18px] text-xs text-red-600">{error}</p>

          <Button type="submit" variant="primary" block loading={submitting} className="mt-1">
            登录
          </Button>

          <p className="mt-4 text-center text-xs text-slate-400">请使用管理员分配的账号登录</p>
        </form>

        <p className="mt-4 text-center text-[11px] text-slate-400">
          {boot?.app_name || '智安鉴'} v{boot?.app_version || '-'} · 本地安全工具，数据不出本机
        </p>
      </div>
    </div>
  )
}
