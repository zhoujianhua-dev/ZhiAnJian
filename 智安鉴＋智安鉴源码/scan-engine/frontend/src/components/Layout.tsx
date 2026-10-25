import { useMemo, useState } from 'react'
import { Outlet, Link, useLocation } from 'react-router-dom'
import {
  Shield,
  LayoutDashboard,
  Plus,
  Database,
  Sun,
  Moon,
  Monitor,
  Bot,
  Settings,
  List,
  Menu,
  X,
  LogOut,
  User,
  ChevronRight,
  Sparkles,
  Activity,
  Radar,
  PanelLeftClose,
  PanelLeftOpen,
  Crown,
} from 'lucide-react'
import clsx from 'clsx'
import { useTheme } from '../contexts/ThemeContext'
import { useAuth } from '../contexts/AuthContext'

const navItems = [
  { to: '/', label: '仪表盘', icon: LayoutDashboard, hint: '总览态势' },
  { to: '/scans', label: '扫描历史', icon: List, hint: '查看任务' },
  { to: '/knowledgebase', label: '知识库', icon: Database, hint: '模板与工具' },
  { to: '/personas', label: 'AI 人格', icon: Bot, hint: '策略与角色' },
]

const pageMeta: Record<string, { title: string; description: string; tag: string }> = {
  '/': { title: '作战总览', description: '统一查看扫描动态、风险聚合与近期趋势。', tag: 'Dashboard' },
  '/scans': { title: '扫描任务栈', description: '按时间轴梳理任务状态、风险评分与可操作记录。', tag: 'Scans' },
  '/new-scan': { title: '创建新任务', description: '配置目标、策略和工具集，生成新的扫描作业。', tag: 'Launch' },
  '/knowledgebase': { title: '知识库中枢', description: '集中维护模板、脚本、字典与内置扫描器。', tag: 'Intel' },
  '/personas': { title: 'AI 策略人格', description: '为主代理和子代理调整分析风格与执行偏好。', tag: 'Agents' },
  '/settings': { title: '系统配置', description: '管理模型、联网搜索与运行时环境参数。', tag: 'Config' },
  '/admin': { title: '管理控制台', description: '审计用户、角色与平台访问状态。', tag: 'Admin' },
}

const themeLabels = {
  light: '亮色',
  dark: '暗色',
  system: '系统',
} as const

function ThemeSwitcher({ theme, setTheme }: { theme: 'light' | 'dark' | 'system'; setTheme: (theme: 'light' | 'dark' | 'system') => void }) {
  const options = [
    { key: 'light' as const, icon: Sun, label: '明亮模式' },
    { key: 'dark' as const, icon: Moon, label: '暗色模式' },
    { key: 'system' as const, icon: Monitor, label: '跟随系统' },
  ]

  return (
    <div className="inline-flex rounded-full border border-white/55 bg-white/75 p-1 shadow-[0_10px_30px_rgba(15,23,42,0.08)] backdrop-blur dark:border-white/10 dark:bg-slate-900/70">
      {options.map(({ key, icon: Icon, label }) => (
        <button
          key={key}
          type="button"
          onClick={() => setTheme(key)}
          className={clsx(
            'flex h-9 w-9 items-center justify-center rounded-full transition-all duration-200',
            theme === key
              ? 'bg-slate-950 text-white shadow-[0_8px_24px_rgba(15,23,42,0.28)] dark:bg-cyan-300 dark:text-slate-950'
              : 'text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white'
          )}
          title={label}
          aria-label={label}
        >
          <Icon className="h-4 w-4" />
        </button>
      ))}
    </div>
  )
}

export default function Layout() {
  const location = useLocation()
  const { theme, resolvedTheme, setTheme } = useTheme()
  const { user, logout, isAdmin } = useAuth()
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const [desktopSidebarOpen, setDesktopSidebarOpen] = useState(true)
  const [userMenuOpen, setUserMenuOpen] = useState(false)

  const currentMeta = useMemo(() => {
    const directMatch = pageMeta[location.pathname]
    if (directMatch) {
      return directMatch
    }

    if (location.pathname.startsWith('/scans/')) {
      return {
        title: '任务详情',
        description: '查看单个扫描任务的实时进度、发现与分析结果。',
        tag: 'Detail',
      }
    }

    return {
      title: 'Hack Scan 控制台',
      description: '集中管理扫描工作流、知识资产与 AI 协作策略。',
      tag: 'Hack Scan',
    }
  }, [location.pathname])

  const userRoleLabel = isAdmin ? '管理员' : '普通用户'
  const userRoleIcon = isAdmin ? Crown : User
  const UserRoleIcon = userRoleIcon

  const shellStatus = resolvedTheme === 'dark' ? '暗色态势已启用' : '日间面板在线'
  const shellAccent = resolvedTheme === 'dark'
    ? 'from-cyan-300/18 via-cyan-200/8 to-transparent'
    : 'from-sky-200/65 via-cyan-100/25 to-transparent'

  const sidebarBase = clsx(
    'flex h-full flex-col overflow-hidden rounded-[28px] border backdrop-blur-xl',
    'border-white/40 bg-[linear-gradient(180deg,rgba(255,255,255,0.9),rgba(244,247,251,0.82))] shadow-[0_30px_80px_rgba(15,23,42,0.12)]',
    'dark:border-white/10 dark:bg-[linear-gradient(180deg,rgba(8,15,29,0.92),rgba(6,11,24,0.84))] dark:shadow-[0_28px_90px_rgba(2,8,23,0.55)]'
  )

  return (
    <div className="app-shell relative min-h-screen overflow-hidden text-slate-900 transition-colors dark:text-slate-100">
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute left-[-10%] top-[-8%] h-[28rem] w-[28rem] rounded-full bg-[radial-gradient(circle,rgba(56,189,248,0.22),transparent_64%)] blur-2xl dark:bg-[radial-gradient(circle,rgba(34,211,238,0.18),transparent_64%)]" />
        <div className="absolute bottom-[-12%] right-[-6%] h-[32rem] w-[32rem] rounded-full bg-[radial-gradient(circle,rgba(251,191,36,0.12),transparent_58%)] blur-3xl dark:bg-[radial-gradient(circle,rgba(14,165,233,0.14),transparent_60%)]" />
        <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/60 to-transparent dark:via-cyan-300/30" />
      </div>

      <header className="sticky top-0 z-40 border-b border-white/35 bg-white/60 backdrop-blur-xl dark:border-white/10 dark:bg-slate-950/45 md:hidden">
        <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4">
          <button
            type="button"
            onClick={() => setMobileMenuOpen(true)}
            className="flex items-center gap-3 rounded-2xl border border-white/50 bg-white/70 px-3 py-2 text-sm font-medium text-slate-700 shadow-[0_12px_30px_rgba(15,23,42,0.08)] dark:border-white/10 dark:bg-slate-900/75 dark:text-slate-200"
            aria-label="打开菜单"
          >
            <Menu className="h-4 w-4" />
            导航
          </button>
          <div className="flex items-center gap-2">
            <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-slate-950 text-white shadow-[0_14px_30px_rgba(15,23,42,0.18)] dark:bg-cyan-300 dark:text-slate-950">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <p className="font-display text-base font-semibold tracking-tight">Hack Scan</p>
              <p className="text-[11px] uppercase tracking-[0.28em] text-slate-500 dark:text-slate-400">Command Mesh</p>
            </div>
          </div>
          <ThemeSwitcher theme={theme} setTheme={setTheme} />
        </div>
      </header>

      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 md:hidden">
          <button
            type="button"
            className="absolute inset-0 bg-slate-950/50 backdrop-blur-sm"
            onClick={() => setMobileMenuOpen(false)}
            aria-label="关闭菜单遮罩"
          />
          <aside className="relative h-full w-[84vw] max-w-sm p-3">
            <div className={clsx(sidebarBase, 'animate-[rise_240ms_ease-out]')}>
              <div className="flex items-start justify-between gap-3 border-b border-slate-200/70 px-5 pb-5 pt-5 dark:border-white/10">
                <div className="flex min-w-0 items-center gap-3">
                  <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-slate-950 text-white dark:bg-cyan-300 dark:text-slate-950">
                    <Shield className="h-6 w-6" />
                  </div>
                  <div className="min-w-0">
                    <p className="font-display truncate text-lg font-semibold">Hack Scan</p>
                    <p className="text-xs uppercase tracking-[0.28em] text-slate-500 dark:text-slate-400">Security Console</p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setMobileMenuOpen(false)}
                  className="flex h-10 w-10 items-center justify-center rounded-2xl border border-slate-200/80 text-slate-500 transition-colors hover:text-slate-900 dark:border-white/10 dark:text-slate-400 dark:hover:text-white"
                  aria-label="关闭菜单"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              <div className="px-5 py-5">
                <Link
                  to="/new-scan"
                  onClick={() => setMobileMenuOpen(false)}
                  className="flex items-center justify-center gap-2 rounded-2xl bg-slate-950 px-4 py-3 text-sm font-semibold text-white shadow-[0_18px_40px_rgba(15,23,42,0.18)] transition-transform hover:-translate-y-0.5 dark:bg-cyan-300 dark:text-slate-950"
                >
                  <Plus className="h-4 w-4" />
                  新建扫描
                </Link>
              </div>

              <nav className="flex-1 space-y-2 px-4 pb-5">
                {navItems.map(item => {
                  const active = location.pathname === item.to
                  return (
                    <Link
                      key={`mobile-${item.to}`}
                      to={item.to}
                      onClick={() => setMobileMenuOpen(false)}
                      className={clsx(
                        'group flex items-center gap-3 rounded-2xl px-4 py-3 transition-all duration-200',
                        active
                          ? 'bg-slate-950 text-white shadow-[0_18px_40px_rgba(15,23,42,0.18)] dark:bg-cyan-300 dark:text-slate-950'
                          : 'text-slate-600 hover:bg-white/85 hover:text-slate-950 dark:text-slate-300 dark:hover:bg-white/6 dark:hover:text-white'
                      )}
                    >
                      <item.icon className="h-5 w-5" />
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-semibold">{item.label}</p>
                        <p className={clsx('text-xs', active ? 'text-white/75 dark:text-slate-800/70' : 'text-slate-400 dark:text-slate-500')}>{item.hint}</p>
                      </div>
                      <ChevronRight className={clsx('h-4 w-4 transition-transform group-hover:translate-x-0.5', active ? 'text-white/70 dark:text-slate-900/70' : 'text-slate-400 dark:text-slate-500')} />
                    </Link>
                  )
                })}
              </nav>

              <div className="border-t border-slate-200/70 p-4 dark:border-white/10">
                <div className="mb-4 rounded-2xl border border-white/40 bg-white/65 p-3 dark:border-white/10 dark:bg-white/5">
                  <p className="text-xs uppercase tracking-[0.24em] text-slate-500 dark:text-slate-400">显示模式</p>
                  <div className="mt-3">
                    <ThemeSwitcher theme={theme} setTheme={setTheme} />
                  </div>
                </div>
                <Link
                  to="/settings"
                  onClick={() => setMobileMenuOpen(false)}
                  className={clsx(
                    'flex items-center gap-3 rounded-2xl px-4 py-3 text-sm font-medium transition-colors',
                    location.pathname === '/settings'
                      ? 'bg-slate-950 text-white dark:bg-cyan-300 dark:text-slate-950'
                      : 'text-slate-600 hover:bg-white/85 hover:text-slate-950 dark:text-slate-300 dark:hover:bg-white/6 dark:hover:text-white'
                  )}
                >
                  <Settings className="h-5 w-5" />
                  系统设置
                </Link>
              </div>
            </div>
          </aside>
        </div>
      )}

      <div className="relative z-10 mx-auto flex min-h-screen w-full max-w-[1680px] gap-4 px-3 pb-3 pt-3 sm:px-4 md:gap-5 md:px-5 md:pb-5 md:pt-5">
        <aside
          className={clsx(
            'hidden md:block',
            desktopSidebarOpen ? 'w-[310px]' : 'w-[108px]'
          )}
        >
          <div className={clsx(sidebarBase, 'sticky top-5')}>
            <div className="border-b border-slate-200/70 px-4 pb-4 pt-4 dark:border-white/10">
              <div className="flex items-start justify-between gap-3">
                <div className={clsx('flex min-w-0 items-center gap-3', !desktopSidebarOpen && 'justify-center')}>
                  <div className="relative flex h-14 w-14 shrink-0 items-center justify-center rounded-[1.35rem] bg-slate-950 text-white shadow-[0_20px_40px_rgba(15,23,42,0.2)] dark:bg-cyan-300 dark:text-slate-950">
                    <Shield className="h-7 w-7" />
                    <span className="absolute inset-0 rounded-[1.35rem] bg-[radial-gradient(circle_at_top,rgba(255,255,255,0.3),transparent_55%)]" />
                  </div>
                  {desktopSidebarOpen && (
                    <div className="min-w-0">
                      <p className="font-display truncate text-xl font-semibold tracking-tight">Hack Scan</p>
                      <p className="text-[11px] uppercase tracking-[0.28em] text-slate-500 dark:text-slate-400">Offensive Control Mesh</p>
                    </div>
                  )}
                </div>
                <button
                  type="button"
                  onClick={() => setDesktopSidebarOpen(open => !open)}
                  className="mt-1 flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl border border-slate-200/80 text-slate-500 transition-colors hover:text-slate-900 dark:border-white/10 dark:text-slate-400 dark:hover:text-white"
                  aria-label={desktopSidebarOpen ? '收起侧边栏' : '展开侧边栏'}
                >
                  {desktopSidebarOpen ? <PanelLeftClose className="h-4 w-4" /> : <PanelLeftOpen className="h-4 w-4" />}
                </button>
              </div>

              {desktopSidebarOpen && (
                <div className={clsx('mt-5 rounded-[24px] border border-white/50 bg-gradient-to-br p-4 dark:border-white/10', shellAccent)}>
                  <div className="flex items-center gap-2 text-xs uppercase tracking-[0.24em] text-slate-600 dark:text-cyan-100/70">
                    <Sparkles className="h-3.5 w-3.5" />
                    System Pulse
                  </div>
                  <p className="mt-3 text-sm font-semibold text-slate-900 dark:text-white">{shellStatus}</p>
                  <p className="mt-1 text-xs leading-5 text-slate-600 dark:text-slate-300">
                    当前主题为 {themeLabels[theme]}，控制台已准备好接收新的任务与分析请求。
                  </p>
                </div>
              )}
            </div>

            <div className="px-4 py-4">
              <Link
                to="/new-scan"
                className={clsx(
                  'group flex items-center justify-center gap-2 rounded-2xl bg-slate-950 px-4 py-3.5 text-sm font-semibold text-white shadow-[0_22px_40px_rgba(15,23,42,0.18)] transition-all hover:-translate-y-0.5 dark:bg-cyan-300 dark:text-slate-950',
                  !desktopSidebarOpen && 'px-0'
                )}
                title="新建扫描"
              >
                <Plus className="h-4.5 w-4.5" />
                {desktopSidebarOpen && <span>新建扫描</span>}
              </Link>
            </div>

            <nav className="flex-1 space-y-2 px-3 pb-3">
              {navItems.map(item => {
                const active = location.pathname === item.to
                return (
                  <Link
                    key={item.to}
                    to={item.to}
                    className={clsx(
                      'group flex items-center rounded-[22px] px-3 py-3 transition-all duration-200',
                      active
                        ? 'bg-slate-950 text-white shadow-[0_18px_36px_rgba(15,23,42,0.16)] dark:bg-cyan-300 dark:text-slate-950'
                        : 'text-slate-600 hover:bg-white/85 hover:text-slate-950 dark:text-slate-300 dark:hover:bg-white/6 dark:hover:text-white',
                      desktopSidebarOpen ? 'gap-3.5' : 'justify-center'
                    )}
                    title={desktopSidebarOpen ? undefined : item.label}
                  >
                    <item.icon className="h-5 w-5 shrink-0" />
                    {desktopSidebarOpen && (
                      <>
                        <div className="min-w-0 flex-1">
                          <p className="truncate text-sm font-semibold">{item.label}</p>
                          <p className={clsx('truncate text-xs', active ? 'text-white/75 dark:text-slate-800/70' : 'text-slate-400 dark:text-slate-500')}>
                            {item.hint}
                          </p>
                        </div>
                        <ChevronRight className={clsx('h-4 w-4 shrink-0 transition-transform group-hover:translate-x-0.5', active ? 'text-white/70 dark:text-slate-900/70' : 'text-slate-400 dark:text-slate-500')} />
                      </>
                    )}
                  </Link>
                )
              })}
            </nav>

            <div className="border-t border-slate-200/70 p-3 dark:border-white/10">
              {desktopSidebarOpen && (
                <div className="mb-3 rounded-[22px] border border-white/45 bg-white/65 p-3.5 dark:border-white/10 dark:bg-white/5">
                  <div className="mb-3 flex items-center justify-between gap-3">
                    <div>
                      <p className="text-xs uppercase tracking-[0.24em] text-slate-500 dark:text-slate-400">显示模式</p>
                      <p className="mt-1 text-sm font-medium text-slate-800 dark:text-slate-200">{themeLabels[theme]}</p>
                    </div>
                    <Radar className="h-4 w-4 text-slate-400 dark:text-slate-500" />
                  </div>
                  <ThemeSwitcher theme={theme} setTheme={setTheme} />
                </div>
              )}
              <Link
                to="/settings"
                className={clsx(
                  'flex items-center rounded-[22px] px-3 py-3 text-sm font-medium transition-colors',
                  location.pathname === '/settings'
                    ? 'bg-slate-950 text-white dark:bg-cyan-300 dark:text-slate-950'
                    : 'text-slate-600 hover:bg-white/85 hover:text-slate-950 dark:text-slate-300 dark:hover:bg-white/6 dark:hover:text-white',
                  desktopSidebarOpen ? 'gap-3' : 'justify-center'
                )}
                title="系统设置"
              >
                <Settings className="h-5 w-5 shrink-0" />
                {desktopSidebarOpen && <span>系统设置</span>}
              </Link>
            </div>
          </div>
        </aside>

        <main className="flex min-w-0 flex-1 flex-col gap-4 md:gap-5">
          <div className="relative z-20 overflow-visible rounded-[28px] border border-white/35 bg-white/70 p-4 shadow-[0_24px_80px_rgba(15,23,42,0.1)] backdrop-blur-xl dark:border-white/10 dark:bg-slate-950/45 dark:shadow-[0_24px_80px_rgba(2,8,23,0.5)] sm:p-5">
            <div className="pointer-events-none absolute inset-0 overflow-hidden rounded-[28px]">
              <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(125,211,252,0.16),transparent_30%),linear-gradient(120deg,rgba(255,255,255,0.08),transparent_55%)] dark:bg-[radial-gradient(circle_at_top_left,rgba(34,211,238,0.14),transparent_28%),linear-gradient(120deg,rgba(255,255,255,0.04),transparent_55%)]" />
            </div>
            <div className="relative z-10 flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
              <div className="min-w-0">
                <div className="mb-3 flex flex-wrap items-center gap-2">
                  <span className="inline-flex items-center rounded-full border border-white/50 bg-white/80 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.24em] text-slate-500 dark:border-white/10 dark:bg-white/6 dark:text-slate-300">
                    {currentMeta.tag}
                  </span>
                  <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/12 px-3 py-1 text-xs font-medium text-emerald-700 dark:bg-emerald-400/12 dark:text-emerald-300">
                    <Activity className="h-3.5 w-3.5" />
                    {shellStatus}
                  </span>
                </div>
                <h1 className="font-display text-3xl font-semibold tracking-tight text-slate-950 dark:text-white sm:text-[2.2rem]">
                  {currentMeta.title}
                </h1>
                <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600 dark:text-slate-300">
                  {currentMeta.description}
                </p>
              </div>

              {user && (
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-end">
                  <div className="grid grid-cols-2 gap-3 sm:w-auto">
                    <div className="rounded-[22px] border border-white/45 bg-white/72 px-4 py-3 dark:border-white/10 dark:bg-white/5">
                      <p className="text-[11px] uppercase tracking-[0.24em] text-slate-500 dark:text-slate-400">角色</p>
                      <p className="mt-2 flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-white">
                        <UserRoleIcon className="h-4 w-4" />
                        {userRoleLabel}
                      </p>
                    </div>
                    <div className="rounded-[22px] border border-white/45 bg-white/72 px-4 py-3 dark:border-white/10 dark:bg-white/5">
                      <p className="text-[11px] uppercase tracking-[0.24em] text-slate-500 dark:text-slate-400">显示</p>
                      <p className="mt-2 text-sm font-semibold text-slate-900 dark:text-white">
                        {resolvedTheme === 'dark' ? 'Night Ops' : 'Daywatch'}
                      </p>
                    </div>
                  </div>

                  <div className="relative">
                    <button
                      type="button"
                      onClick={() => setUserMenuOpen(open => !open)}
                      className="flex min-w-[220px] items-center gap-3 rounded-[24px] border border-white/50 bg-white/78 px-4 py-3 text-left shadow-[0_12px_30px_rgba(15,23,42,0.06)] transition-colors hover:bg-white/90 dark:border-white/10 dark:bg-white/5 dark:hover:bg-white/8"
                      title="用户菜单"
                    >
                      <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl bg-slate-950 text-white dark:bg-cyan-300 dark:text-slate-950">
                        <User className="h-5 w-5" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-semibold text-slate-900 dark:text-white">{user.username}</p>
                        <p className="truncate text-xs text-slate-500 dark:text-slate-400">{user.email}</p>
                      </div>
                      <ChevronRight className={clsx('h-4 w-4 shrink-0 text-slate-400 transition-transform dark:text-slate-500', userMenuOpen && 'rotate-90')} />
                    </button>

                    {userMenuOpen && (
                      <div className="absolute right-0 top-[calc(100%+0.75rem)] z-50 w-full min-w-[240px] overflow-hidden rounded-[24px] border border-white/50 bg-white/92 p-2 shadow-[0_24px_60px_rgba(15,23,42,0.16)] backdrop-blur-xl dark:border-white/10 dark:bg-slate-900/92">
                        <div className="rounded-[18px] border border-slate-200/70 bg-slate-50/90 p-3 dark:border-white/8 dark:bg-white/5">
                          <p className="text-xs uppercase tracking-[0.22em] text-slate-500 dark:text-slate-400">当前账户</p>
                          <p className="mt-2 text-sm font-semibold text-slate-900 dark:text-white">{user.username}</p>
                          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{userRoleLabel}</p>
                        </div>
                        <button
                          type="button"
                          onClick={() => {
                            logout()
                            setUserMenuOpen(false)
                          }}
                          className="mt-2 flex w-full items-center gap-3 rounded-[18px] px-4 py-3 text-sm font-medium text-rose-600 transition-colors hover:bg-rose-500/10 dark:text-rose-300 dark:hover:bg-rose-500/10"
                        >
                          <LogOut className="h-4 w-4" />
                          退出登录
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>

          <div className="page-stage relative z-0 min-h-[calc(100vh-12rem)] flex-1 overflow-hidden rounded-[30px] border border-white/35 bg-white/58 p-3 shadow-[0_26px_90px_rgba(15,23,42,0.08)] backdrop-blur-xl dark:border-white/10 dark:bg-slate-950/35 dark:shadow-[0_28px_90px_rgba(2,8,23,0.52)] sm:p-4 md:p-5">
            <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(180deg,rgba(255,255,255,0.08),transparent_20%),radial-gradient(circle_at_top_right,rgba(56,189,248,0.08),transparent_28%)] dark:bg-[linear-gradient(180deg,rgba(255,255,255,0.03),transparent_20%),radial-gradient(circle_at_top_right,rgba(34,211,238,0.1),transparent_26%)]" />
            <div className="relative h-full overflow-auto rounded-[24px] border border-white/45 bg-[linear-gradient(180deg,rgba(255,255,255,0.78),rgba(248,250,252,0.7))] p-4 shadow-[inset_0_1px_0_rgba(255,255,255,0.4)] dark:border-white/8 dark:bg-[linear-gradient(180deg,rgba(7,14,27,0.75),rgba(5,10,22,0.7))] sm:p-5 md:p-6">
              <Outlet />
            </div>
          </div>
        </main>
      </div>
    </div>
  )
}
