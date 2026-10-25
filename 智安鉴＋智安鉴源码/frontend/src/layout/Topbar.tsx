import { useEffect, useRef, useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { ChevronDown, LogOut, Menu, Sparkles, UserCog, Users } from 'lucide-react'
import { cn } from '@/lib/cn'
import { useAuth } from '@/store/auth'
import { ChangePasswordModal } from './ChangePasswordModal'
import { resolveCrumb } from './nav'

export function Topbar({ onMenu }: { onMenu: () => void }) {
  const { user, logout } = useAuth()
  const { pathname } = useLocation()
  const navigate = useNavigate()
  const crumb = resolveCrumb(pathname)
  const [menuOpen, setMenuOpen] = useState(false)
  const [pwdOpen, setPwdOpen] = useState(false)
  const menuRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!menuOpen) return
    const onClick = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenuOpen(false)
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMenuOpen(false)
    }
    document.addEventListener('mousedown', onClick)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onClick)
      document.removeEventListener('keydown', onKey)
    }
  }, [menuOpen])

  async function doLogout() {
    setMenuOpen(false)
    await logout()
    navigate('/login', { replace: true })
  }

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-line bg-surface px-4 lg:px-6">
      <button
        type="button"
        onClick={onMenu}
        className="-ml-1 rounded p-1.5 text-slate-500 hover:bg-slate-100 lg:hidden"
        aria-label="打开菜单"
      >
        <Menu size={18} />
      </button>

      <div className="flex min-w-0 items-baseline gap-2">
        {crumb.group ? <span className="hidden text-xs text-slate-400 sm:inline">{crumb.group}</span> : null}
        {crumb.group ? <span className="hidden text-slate-300 sm:inline">/</span> : null}
        <h1 className="truncate text-[15px] font-semibold text-slate-900">{crumb.title}</h1>
      </div>

      <div className="ml-auto flex items-center gap-2">
        <Link
          to="/reports/ai"
          className="inline-flex h-[30px] items-center gap-1.5 rounded-md bg-primary px-2.5 text-xs font-medium text-white transition-colors hover:bg-primary-hover"
        >
          <Sparkles size={13} />
          <span className="hidden sm:inline">AI 生成报告</span>
          <span className="sm:hidden">AI</span>
        </Link>

        {user ? (
          <div className="relative" ref={menuRef}>
            <button
              type="button"
              onClick={() => setMenuOpen((v) => !v)}
              aria-haspopup="menu"
              aria-expanded={menuOpen}
              className="flex items-center gap-2 rounded-md border border-line bg-white py-1 pl-1 pr-2 transition-colors hover:border-line-strong"
            >
              <span className="flex h-7 w-7 items-center justify-center rounded-full bg-primary text-xs font-semibold text-white">
                {(user.display_name || user.username).slice(0, 1)}
              </span>
              <span className="hidden text-left leading-tight sm:block">
                <span className="block max-w-[120px] truncate text-[12.5px] font-medium text-slate-800">
                  {user.display_name || user.username}
                </span>
                <span className="block text-[11px] text-slate-500">
                  {user.role === 'admin' ? '管理员' : '普通用户'}
                </span>
              </span>
              <ChevronDown size={13} className={cn('text-slate-400 transition-transform', menuOpen && 'rotate-180')} />
            </button>

            {menuOpen ? (
              <div
                role="menu"
                className="absolute right-0 top-[calc(100%+6px)] w-48 animate-slide-in rounded-md border border-line bg-white py-1 shadow-pop"
              >
                <div className="border-b border-line px-3 pb-2 pt-1.5">
                  <div className="truncate text-[13px] font-medium text-slate-900">
                    {user.display_name || user.username}
                  </div>
                  <div className="truncate text-xs text-slate-500">{user.username}</div>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setMenuOpen(false)
                    setPwdOpen(true)
                  }}
                  className="flex w-full items-center gap-2 px-3 py-2 text-left text-[13px] text-slate-700 hover:bg-slate-50"
                >
                  <UserCog size={14} className="text-slate-400" />
                  修改密码
                </button>
                {user.role === 'admin' ? (
                  <Link
                    to="/users"
                    onClick={() => setMenuOpen(false)}
                    className="flex w-full items-center gap-2 px-3 py-2 text-left text-[13px] text-slate-700 hover:bg-slate-50"
                  >
                    <Users size={14} className="text-slate-400" />
                    用户管理
                  </Link>
                ) : null}
                <div className="my-1 h-px bg-line" />
                <button
                  type="button"
                  onClick={doLogout}
                  className="flex w-full items-center gap-2 px-3 py-2 text-left text-[13px] text-red-600 hover:bg-red-50"
                >
                  <LogOut size={14} />
                  退出登录
                </button>
              </div>
            ) : null}
          </div>
        ) : null}
      </div>

      <ChangePasswordModal open={pwdOpen} onClose={() => setPwdOpen(false)} />
    </header>
  )
}
