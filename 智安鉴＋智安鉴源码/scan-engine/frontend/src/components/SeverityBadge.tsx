import clsx from 'clsx'

interface SeverityBadgeProps {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  className?: string
}

const severityColors = {
  critical: 'bg-red-600',
  high: 'bg-orange-600',
  medium: 'bg-yellow-600',
  low: 'bg-green-600',
  info: 'bg-blue-600',
}

const severityLabels: Record<string, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
}

export default function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  return (
    <span
      className={clsx(
        'px-2 py-1 text-xs font-semibold uppercase rounded text-white',
        severityColors[severity],
        className
      )}
    >
      {severityLabels[severity] || severity}
    </span>
  )
}
