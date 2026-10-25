import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { api, ensureCsrf, resetCsrf } from '@/lib/api'
import { applyThemeColor } from '@/lib/theme'

export interface CurrentUser {
  id: number
  username: string
  display_name: string
  role: 'admin' | 'user'
  role_cn?: string
  last_login_at?: string | null
  default_pwd?: boolean
}

export interface Bootstrap {
  app_name: string
  app_title: string
  app_subtitle: string
  app_version: string
  theme_color: string
  background: string
  background_overlay: number
  background_blur: number
  user: CurrentUser | null
  default_pwd: boolean
}

interface AuthContextValue {
  boot: Bootstrap | null
  user: CurrentUser | null
  loading: boolean
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
  refresh: () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [boot, setBoot] = useState<Bootstrap | null>(null)
  const [loading, setLoading] = useState(true)

  const refresh = useCallback(async () => {
    const res = await api.get<Bootstrap>('/api/app/bootstrap')
    const data = res.data as Bootstrap
    setBoot(data)
    applyThemeColor(data.theme_color)
    const brand =
      data.app_title && data.app_title !== data.app_name
        ? `${data.app_title} · ${data.app_name}`
        : data.app_name
    document.title = data.user ? brand : `登录 · ${data.app_name}`
  }, [])

  useEffect(() => {
    refresh()
      .catch(() => setBoot(null))
      .finally(() => setLoading(false))
  }, [refresh])

  const login = useCallback(
    async (username: string, password: string) => {
      await api.post('/api/auth/login', { username, password })
      // 登录会重开会话并换发 CSRF token，必须丢弃旧值
      resetCsrf()
      await ensureCsrf()
      await refresh()
    },
    [refresh],
  )

  const logout = useCallback(async () => {
    try {
      await api.post('/api/auth/logout')
    } finally {
      resetCsrf()
      setBoot((b) => (b ? { ...b, user: null, default_pwd: false } : b))
    }
  }, [])

  const value = useMemo<AuthContextValue>(
    () => ({ boot, user: boot?.user || null, loading, login, logout, refresh }),
    [boot, loading, login, logout, refresh],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth 必须在 AuthProvider 内使用')
  return ctx
}

function Splash() {
  return (
    <div className="flex h-screen items-center justify-center bg-canvas">
      <div className="flex items-center gap-2 text-[13px] text-slate-500">
        <span className="h-4 w-4 animate-spin rounded-full border-2 border-line-strong border-t-primary" />
        正在加载…
      </div>
    </div>
  )
}

export function Forbidden({ message = '需要管理员权限' }: { message?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-line bg-surface py-20">
      <p className="text-3xl font-semibold text-slate-300">403</p>
      <p className="text-[13px] text-slate-600">{message}</p>
    </div>
  )
}

/** 路由守卫：未登录跳登录页（带 next），adminOnly 校验角色 */
export function RequireAuth({ children, adminOnly }: { children: ReactNode; adminOnly?: boolean }) {
  const { user, loading } = useAuth()
  const location = useLocation()

  if (loading) return <Splash />
  if (!user) {
    const next = encodeURIComponent(location.pathname + location.search)
    return <Navigate to={`/login?next=${next}`} replace />
  }
  if (adminOnly && user.role !== 'admin') return <Forbidden />
  return <>{children}</>
}
