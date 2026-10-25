import { useEffect, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { X } from 'lucide-react'
import { cn } from '@/lib/cn'

const SIZES = {
  sm: 'max-w-[460px]',
  md: 'max-w-[640px]',
  lg: 'max-w-[860px]',
  xl: 'max-w-[1080px]',
} as const

export type ModalSize = keyof typeof SIZES

interface ModalProps {
  open: boolean
  onClose: () => void
  title?: ReactNode
  footer?: ReactNode
  size?: ModalSize
  children: ReactNode
  /** 点击遮罩是否关闭，默认 true */
  maskClosable?: boolean
  bodyClassName?: string
}

export function Modal({
  open,
  onClose,
  title,
  footer,
  size = 'md',
  children,
  maskClosable = true,
  bodyClassName,
}: ModalProps) {
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    const prev = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', onKey)
      document.body.style.overflow = prev
    }
  }, [open, onClose])

  if (!open) return null

  return createPortal(
    <div
      className="fixed inset-0 z-[400] overflow-y-auto bg-slate-900/45 p-4 animate-fade-in sm:py-10"
      onMouseDown={(e) => {
        if (maskClosable && e.target === e.currentTarget) onClose()
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        className={cn(
          'mx-auto flex w-full flex-col overflow-hidden rounded-lg border border-line bg-white shadow-pop',
          SIZES[size],
        )}
      >
        <div className="flex items-center gap-3 border-b border-line px-5 py-3.5">
          <h3 className="min-w-0 flex-1 truncate text-[15px] font-semibold text-slate-900">{title}</h3>
          <button
            type="button"
            onClick={onClose}
            className="rounded p-1 text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-600"
            aria-label="关闭"
          >
            <X size={16} />
          </button>
        </div>
        <div className={cn('max-h-[calc(100vh-220px)] overflow-y-auto px-5 py-4', bodyClassName)}>{children}</div>
        {footer ? (
          <div className="flex items-center justify-end gap-2 border-t border-line bg-slate-50/60 px-5 py-3">
            {footer}
          </div>
        ) : null}
      </div>
    </div>,
    document.body,
  )
}
