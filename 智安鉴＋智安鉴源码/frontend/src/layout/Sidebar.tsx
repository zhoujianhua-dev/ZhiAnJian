import { useEffect, useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { ChevronRight, ShieldCheck, X } from 'lucide-react'
import { cn } from '@/lib/cn'
import { useAuth } from '@/store/auth'
import { NAV_GROUPS, isItemActive } from './nav'

export function Sidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { user, boot } = useAuth()
  const { pathname } = useLocation()
  const [expanded, setExpanded] = useState<Record<string, boolean>>({})

  // 进入子路由时自动展开所在分组
  useEffect(() => {
    NAV_GROUPS.forEach((group) => {
      group.items.forEach((item) => {
        if (item.children && isItemActive(item, pathname)) {
          setExpanded((prev) => (prev[item.to] ? prev : { ...prev, [item.to]: true }))
        }
      })
    })
  }, [pathname])

  return (
    <>
      {open ? (
        <div className="fixed inset-0 z-40 bg-slate-900/40 lg:hidden" onClick={onClose} aria-hidden />
      ) : null}

      <aside
        className={cn(
          'fixed inset-y-0 left-0 z-50 flex w-[232px] shrink-0 flex-col border-r border-line bg-surface transition-transform lg:sticky lg:top-0 lg:h-screen lg:translate-x-0',
          open ? 'translate-x-0' : '-translate-x-full',
        )}
      >
        <div className="flex h-14 items-center gap-2.5 border-b border-line px-4">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-primary text-white">
            <ShieldCheck size={18} />
          </span>
          <div className="min-w-0 flex-1">
            <div className="truncate text-[14px] font-semibold leading-tight text-slate-900">
              {boot?.app_name || '智安鉴'}
            </div>
            <div className="truncate text-[11px] leading-tight text-slate-500">
              {boot?.app_subtitle || '智能安全检测与漏洞报告系统'}
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded p-1 text-slate-400 hover:bg-slate-100 lg:hidden"
            aria-label="关闭菜单"
          >
            <X size={16} />
          </button>
        </div>

        <nav className="flex-1 overflow-y-auto px-2 py-3">
          {NAV_GROUPS.map((group, gi) => {
            const items = group.items.filter((it) => !it.adminOnly || user?.role === 'admin')
            if (!items.length) return null
            return (
              <div key={group.title || `g-${gi}`} className={cn(gi > 0 && 'mt-4')}>
                {group.title ? (
                  <div className="px-2.5 pb-1.5 text-[11px] font-medium tracking-wide text-slate-400">
                    {group.title}
                  </div>
                ) : null}
                <ul className="flex flex-col gap-0.5">
                  {items.map((item) => {
                    const active = isItemActive(item, pathname)
                    const isOpen = expanded[item.to] ?? false
                    const Icon = item.icon
                    return (
                      <li key={item.to}>
                        {item.children ? (
                          <>
                            <button
                              type="button"
                              onClick={() => setExpanded((p) => ({ ...p, [item.to]: !isOpen }))}
                              className={cn(
                                'flex w-full items-center gap-2.5 rounded-md px-2.5 py-[7px] text-left text-[13px] transition-colors',
                                active
                                  ? 'bg-primary-soft font-medium text-primary'
                                  : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900',
                              )}
                            >
                              <Icon size={16} className="shrink-0" />
                              <span className="min-w-0 flex-1 truncate">{item.label}</span>
                              <ChevronRight
                                size={13}
                                className={cn('shrink-0 transition-transform', isOpen && 'rotate-90')}
                              />
                            </button>
                            {isOpen ? (
                              <ul className="mb-1 mt-0.5 flex flex-col gap-0.5 pl-8">
                                {item.children.map((child) => {
                                  const childActive = pathname.replace(/\/+$/, '') === child.to
                                  return (
                                    <li key={child.to}>
                                      <Link
                                        to={child.to}
                                        onClick={onClose}
                                        className={cn(
                                          'block rounded-md px-2.5 py-1.5 text-[12.5px] transition-colors',
                                          childActive
                                            ? 'bg-primary-soft font-medium text-primary'
                                            : 'text-slate-500 hover:bg-slate-100 hover:text-slate-900',
                                        )}
                                      >
                                        {child.label}
                                      </Link>
                                    </li>
                                  )
                                })}
                              </ul>
                            ) : null}
                          </>
                        ) : (
                          <Link
                            to={item.to}
                            onClick={onClose}
                            className={cn(
                              'flex items-center gap-2.5 rounded-md px-2.5 py-[7px] text-[13px] transition-colors',
                              active
                                ? 'bg-primary-soft font-medium text-primary'
                                : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900',
                            )}
                          >
                            <Icon size={16} className="shrink-0" />
                            <span className="min-w-0 flex-1 truncate">{item.label}</span>
                          </Link>
                        )}
                      </li>
                    )
                  })}
                </ul>
              </div>
            )
          })}
        </nav>

        <div className="border-t border-line px-4 py-3 text-[11px] leading-5 text-slate-400">
          {boot?.app_name || '智安鉴'} v{boot?.app_version || '-'}
          <br />
          本地安全工具 · 数据不出本机
        </div>
      </aside>
    </>
  )
}
