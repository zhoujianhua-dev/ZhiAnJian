import { ChevronLeft, ChevronRight, Inbox, Loader2 } from 'lucide-react'
import type { ReactNode } from 'react'
import { cn } from '@/lib/cn'

export function EmptyState({
  title = '暂无数据',
  description,
  action,
  className,
}: {
  title?: ReactNode
  description?: ReactNode
  action?: ReactNode
  className?: string
}) {
  return (
    <div className={cn('flex flex-col items-center justify-center px-4 py-10 text-center', className)}>
      <Inbox size={28} className="mb-2 text-slate-300" />
      <p className="text-[13px] font-medium text-slate-600">{title}</p>
      {description ? <p className="mt-1 text-xs leading-5 text-slate-400">{description}</p> : null}
      {action ? <div className="mt-3">{action}</div> : null}
    </div>
  )
}

export function LoadingBlock({ text = '加载中…', className }: { text?: string; className?: string }) {
  return (
    <div className={cn('flex items-center justify-center gap-2 py-12 text-[13px] text-slate-500', className)}>
      <Loader2 size={16} className="animate-spin text-primary" />
      {text}
    </div>
  )
}

export function ErrorBlock({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-4 py-10 text-center">
      <p className="text-[13px] text-red-600">{message}</p>
      {onRetry ? (
        <button type="button" onClick={onRetry} className="text-[13px] text-primary hover:underline">
          重试
        </button>
      ) : null}
    </div>
  )
}

interface PaginationProps {
  page: number
  total: number
  limit: number
  onChange: (page: number) => void
  className?: string
}

export function Pagination({ page, total, limit, onChange, className }: PaginationProps) {
  const pages = Math.max(1, Math.ceil(total / Math.max(1, limit)))
  const current = Math.min(Math.max(1, page), pages)
  const range: Array<number | '...'> = []
  for (let p = 1; p <= pages; p += 1) {
    if (p === 1 || p === pages || Math.abs(p - current) <= 2) range.push(p)
    else if (range[range.length - 1] !== '...') range.push('...')
  }

  const btn =
    'inline-flex h-7 min-w-7 items-center justify-center rounded border border-line bg-white px-1.5 text-xs text-slate-600 transition-colors'

  return (
    <div className={cn('flex flex-wrap items-center justify-end gap-1.5', className)}>
      <span className="mr-1 text-xs text-slate-500">
        共 <span className="tnum font-medium text-slate-700">{total}</span> 条
      </span>
      <button
        type="button"
        className={cn(btn, 'hover:border-primary hover:text-primary disabled:opacity-40 disabled:hover:border-line disabled:hover:text-slate-600')}
        disabled={current <= 1}
        onClick={() => onChange(current - 1)}
        aria-label="上一页"
      >
        <ChevronLeft size={13} />
      </button>
      {range.map((p, i) =>
        p === '...' ? (
          <span key={`gap-${i}`} className="px-1 text-xs text-slate-400">
            …
          </span>
        ) : (
          <button
            key={p}
            type="button"
            onClick={() => onChange(p)}
            className={cn(
              btn,
              p === current
                ? 'border-primary bg-primary text-white hover:text-white'
                : 'hover:border-primary hover:text-primary',
            )}
          >
            {p}
          </button>
        ),
      )}
      <button
        type="button"
        className={cn(btn, 'hover:border-primary hover:text-primary disabled:opacity-40 disabled:hover:border-line disabled:hover:text-slate-600')}
        disabled={current >= pages}
        onClick={() => onChange(current + 1)}
        aria-label="下一页"
      >
        <ChevronRight size={13} />
      </button>
    </div>
  )
}
