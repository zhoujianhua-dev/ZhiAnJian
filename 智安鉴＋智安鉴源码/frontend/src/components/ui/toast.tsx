import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react'
import { AlertTriangle, CheckCircle2, Info, X, XCircle } from 'lucide-react'
import { cn } from '@/lib/cn'

type ToastType = 'success' | 'error' | 'info' | 'warning'

interface ToastItem {
  id: number
  type: ToastType
  message: string
}

interface ToastApi {
  success: (msg: string) => void
  error: (msg: string) => void
  info: (msg: string) => void
  warning: (msg: string) => void
  show: (msg: string, type?: ToastType) => void
}

const ToastContext = createContext<ToastApi | null>(null)

const ICONS: Record<ToastType, ReactNode> = {
  success: <CheckCircle2 size={16} className="text-emerald-600" />,
  error: <XCircle size={16} className="text-red-600" />,
  info: <Info size={16} className="text-sky-600" />,
  warning: <AlertTriangle size={16} className="text-amber-600" />,
}

const BAR: Record<ToastType, string> = {
  success: 'bg-emerald-500',
  error: 'bg-red-500',
  info: 'bg-sky-500',
  warning: 'bg-amber-500',
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([])
  const seq = useRef(0)

  const remove = useCallback((id: number) => {
    setItems((list) => list.filter((t) => t.id !== id))
  }, [])

  const show = useCallback(
    (message: string, type: ToastType = 'success') => {
      const id = ++seq.current
      setItems((list) => [...list, { id, type, message }])
      window.setTimeout(() => remove(id), type === 'error' ? 4200 : 2600)
    },
    [remove],
  )

  const value = useMemo<ToastApi>(
    () => ({
      show,
      success: (m: string) => show(m, 'success'),
      error: (m: string) => show(m, 'error'),
      info: (m: string) => show(m, 'info'),
      warning: (m: string) => show(m, 'warning'),
    }),
    [show],
  )

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="pointer-events-none fixed right-4 top-4 z-[600] flex w-[340px] max-w-[calc(100vw-2rem)] flex-col gap-2">
        {items.map((t) => (
          <div
            key={t.id}
            className="pointer-events-auto flex animate-slide-in items-start gap-2.5 rounded-md border border-line bg-white px-3.5 py-2.5 shadow-pop"
          >
            <span className={cn('mt-[3px] h-3.5 w-[3px] shrink-0 rounded-full', BAR[t.type])} />
            <span className="mt-[1px] shrink-0">{ICONS[t.type]}</span>
            <p className="min-w-0 flex-1 text-[13px] leading-5 text-slate-700">{t.message}</p>
            <button
              type="button"
              onClick={() => remove(t.id)}
              className="mt-[2px] shrink-0 rounded p-0.5 text-slate-400 hover:bg-slate-100 hover:text-slate-600"
              aria-label="关闭"
            >
              <X size={13} />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}

export function useToast() {
  const ctx = useContext(ToastContext)
  if (!ctx) throw new Error('useToast 必须在 ToastProvider 内使用')
  return ctx
}
