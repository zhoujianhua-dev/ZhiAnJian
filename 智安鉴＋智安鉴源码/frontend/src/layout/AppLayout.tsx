import { useState } from 'react'
import { Outlet } from 'react-router-dom'
import { AlertTriangle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useAuth } from '@/store/auth'
import { ChangePasswordModal } from './ChangePasswordModal'
import { Sidebar } from './Sidebar'
import { Topbar } from './Topbar'

const DISMISS_KEY = 'zz.pwdTipDismissed'

export function AppLayout() {
  const { boot, user } = useAuth()
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [pwdOpen, setPwdOpen] = useState(false)
  const [tipDismissed, setTipDismissed] = useState(() => sessionStorage.getItem(DISMISS_KEY) === '1')

  const showDefaultPwdTip = !!user?.default_pwd && !tipDismissed

  return (
    <div className="flex min-h-screen">
      {boot?.background ? (
        <div className="pointer-events-none fixed inset-0 -z-10">
          <div
            className="absolute inset-0 bg-cover bg-center"
            style={{
              backgroundImage: `url(/media/backgrounds/${boot.background})`,
              filter: boot.background_blur ? `blur(${boot.background_blur}px)` : undefined,
              transform: boot.background_blur ? 'scale(1.04)' : undefined,
            }}
          />
          <div
            className="absolute inset-0"
            style={{ background: `rgba(246, 247, 249, ${boot.background_overlay ?? 0.35})` }}
          />
        </div>
      ) : null}

      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />

      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar onMenu={() => setSidebarOpen(true)} />
        <main className="flex-1 px-4 py-4 lg:px-6 lg:py-5">
          <div className="mx-auto w-full max-w-[1440px]">
            {showDefaultPwdTip ? (
              <div className="mb-4 flex flex-wrap items-center gap-2.5 rounded-md border border-amber-200 bg-amber-50 px-3.5 py-2.5 text-[13px] text-amber-800">
                <AlertTriangle size={16} className="shrink-0" />
                <span className="min-w-0 flex-1">
                  当前账号仍在使用内置默认密码，任何知道默认口令的人都能登录，建议立即修改。
                </span>
                <Button size="sm" variant="warning" onClick={() => setPwdOpen(true)}>
                  修改密码
                </Button>
                <button
                  type="button"
                  onClick={() => {
                    sessionStorage.setItem(DISMISS_KEY, '1')
                    setTipDismissed(true)
                  }}
                  className="text-xs text-amber-700/70 hover:text-amber-900"
                >
                  稍后提醒
                </button>
              </div>
            ) : null}
            <Outlet />
          </div>
        </main>
      </div>

      <ChangePasswordModal open={pwdOpen} onClose={() => setPwdOpen(false)} />
    </div>
  )
}
