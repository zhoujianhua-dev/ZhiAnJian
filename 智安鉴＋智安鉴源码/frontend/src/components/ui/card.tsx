import type { ReactNode } from 'react'
import { cn } from '@/lib/cn'

export function Card({ className, children }: { className?: string; children: ReactNode }) {
  return (
    <section className={cn('rounded-lg border border-line bg-surface shadow-card', className)}>
      {children}
    </section>
  )
}

interface CardHeaderProps {
  title: ReactNode
  description?: ReactNode
  actions?: ReactNode
  className?: string
}

export function CardHeader({ title, description, actions, className }: CardHeaderProps) {
  return (
    <div className={cn('flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-line px-4 py-3', className)}>
      <div className="min-w-0 flex-1">
        <h2 className="text-[14px] font-semibold text-slate-900">{title}</h2>
        {description ? <p className="mt-0.5 text-xs text-slate-500">{description}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  )
}

export function CardBody({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={cn('p-4', className)}>{children}</div>
}

export function CardFooter({ className, children }: { className?: string; children: ReactNode }) {
  return (
    <div className={cn('flex flex-wrap items-center gap-2 border-t border-line px-4 py-3', className)}>
      {children}
    </div>
  )
}

/** 页面顶部的说明块（工具页等需要一句引导语的场景） */
export function PageIntro({
  icon,
  title,
  description,
  actions,
}: {
  icon?: ReactNode
  title: ReactNode
  description?: ReactNode
  actions?: ReactNode
}) {
  return (
    <div className="mb-4 flex flex-wrap items-center gap-3 rounded-lg border border-line bg-surface px-4 py-3.5 shadow-card">
      {icon ? (
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-primary-line bg-primary-soft text-primary">
          {icon}
        </span>
      ) : null}
      <div className="min-w-0 flex-1">
        <h1 className="text-[15px] font-semibold text-slate-900">{title}</h1>
        {description ? <p className="mt-0.5 text-xs leading-5 text-slate-500">{description}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  )
}
