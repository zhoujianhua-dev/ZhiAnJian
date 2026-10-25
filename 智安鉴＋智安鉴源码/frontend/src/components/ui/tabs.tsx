import type { ReactNode } from 'react'
import { cn } from '@/lib/cn'

export interface TabItem {
  key: string
  label: ReactNode
  icon?: ReactNode
  badge?: ReactNode
  disabled?: boolean
}

interface TabsProps {
  items: TabItem[]
  value: string
  onChange: (key: string) => void
  className?: string
  /** line：下划线式（默认）；segment：分段控件 */
  variant?: 'line' | 'segment'
}

export function Tabs({ items, value, onChange, className, variant = 'line' }: TabsProps) {
  if (variant === 'segment') {
    return (
      <div className={cn('inline-flex rounded-md border border-line bg-slate-50 p-0.5', className)}>
        {items.map((it) => (
          <button
            key={it.key}
            type="button"
            disabled={it.disabled}
            onClick={() => onChange(it.key)}
            className={cn(
              'inline-flex items-center gap-1.5 rounded px-3 py-1.5 text-[13px] font-medium transition-colors disabled:opacity-50',
              it.key === value
                ? 'border border-line bg-white text-slate-900 shadow-card'
                : 'text-slate-500 hover:text-slate-800',
            )}
          >
            {it.icon}
            {it.label}
            {it.badge}
          </button>
        ))}
      </div>
    )
  }

  return (
    <div className={cn('flex gap-1 overflow-x-auto border-b border-line', className)}>
      {items.map((it) => (
        <button
          key={it.key}
          type="button"
          disabled={it.disabled}
          onClick={() => onChange(it.key)}
          className={cn(
            'relative inline-flex items-center gap-1.5 whitespace-nowrap px-3 py-2.5 text-[13px] font-medium transition-colors disabled:opacity-50',
            it.key === value ? 'text-primary' : 'text-slate-500 hover:text-slate-800',
          )}
        >
          {it.icon}
          {it.label}
          {it.badge}
          {it.key === value ? (
            <span className="absolute inset-x-2 -bottom-px h-0.5 rounded-full bg-primary" />
          ) : null}
        </button>
      ))}
    </div>
  )
}
