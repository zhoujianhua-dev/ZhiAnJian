import type { ReactNode } from 'react'
import { cn } from '@/lib/cn'
import {
  LIFECYCLE_STYLE,
  SEVERITY_STYLE,
  lifecycleLabel,
  lifecycleOf,
  severityLabel,
  severityOf,
} from '@/lib/format'

export type BadgeTone = 'slate' | 'blue' | 'green' | 'red' | 'amber' | 'sky' | 'violet' | 'emerald'

const TONES: Record<BadgeTone, string> = {
  slate: 'bg-slate-100 text-slate-600 border-slate-200',
  blue: 'bg-blue-50 text-blue-700 border-blue-200',
  green: 'bg-green-50 text-green-700 border-green-200',
  emerald: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  red: 'bg-red-50 text-red-700 border-red-200',
  amber: 'bg-amber-50 text-amber-700 border-amber-200',
  sky: 'bg-sky-50 text-sky-700 border-sky-200',
  violet: 'bg-violet-50 text-violet-700 border-violet-200',
}

export function Badge({
  tone = 'slate',
  children,
  className,
  dot,
}: {
  tone?: BadgeTone
  children: ReactNode
  className?: string
  dot?: string
}) {
  return (
    <span
      className={cn(
        'inline-flex w-fit items-center gap-1 whitespace-nowrap rounded border px-1.5 py-px text-[11.5px] font-medium leading-5',
        TONES[tone],
        className,
      )}
    >
      {dot ? <span className="h-1.5 w-1.5 rounded-full" style={{ background: dot }} /> : null}
      {children}
    </span>
  )
}

export function SeverityBadge({ severity, className }: { severity?: string | null; className?: string }) {
  const key = severityOf(severity)
  return <span className={cn('inline-flex w-fit items-center rounded border px-1.5 py-px text-[11.5px] font-medium leading-5', SEVERITY_STYLE[key], className)}>
    {severityLabel(key)}
  </span>
}

export function LifecycleBadge({ lifecycle, className }: { lifecycle?: string | null; className?: string }) {
  const key = lifecycleOf(lifecycle)
  return (
    <span className={cn('inline-flex w-fit items-center rounded border px-1.5 py-px text-[11.5px] font-medium leading-5', LIFECYCLE_STYLE[key], className)}>
      {lifecycleLabel(key)}
    </span>
  )
}

export function TagChip({ children, onRemove }: { children: ReactNode; onRemove?: () => void }) {
  return (
    <span className="inline-flex w-fit items-center gap-1 whitespace-nowrap rounded border border-line bg-slate-50 px-1.5 py-px text-[11.5px] leading-5 text-slate-600">
      {children}
      {onRemove ? (
        <button type="button" onClick={onRemove} className="text-slate-400 hover:text-red-500" aria-label="移除">
          ×
        </button>
      ) : null}
    </span>
  )
}
