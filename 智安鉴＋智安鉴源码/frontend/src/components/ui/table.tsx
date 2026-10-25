import type { ReactNode } from 'react'
import { Loader2 } from 'lucide-react'
import { cn } from '@/lib/cn'

export interface Column<T> {
  key: string
  title: ReactNode
  render: (row: T, index: number) => ReactNode
  className?: string
  headClassName?: string
  width?: number | string
  align?: 'left' | 'center' | 'right'
}

const ALIGN = { left: 'text-left', center: 'text-center', right: 'text-right' } as const

interface DataTableProps<T> {
  columns: Column<T>[]
  rows: T[]
  rowKey: (row: T, index: number) => string | number
  loading?: boolean
  loadingText?: string
  empty?: ReactNode
  /** 勾选列 */
  selectable?: boolean
  selectedKeys?: Array<string | number>
  onSelectedChange?: (keys: Array<string | number>) => void
  isRowSelectable?: (row: T) => boolean
  onRowClick?: (row: T) => void
  rowClassName?: (row: T) => string | undefined
  className?: string
}

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  loading,
  loadingText = '加载中…',
  empty,
  selectable,
  selectedKeys = [],
  onSelectedChange,
  isRowSelectable,
  onRowClick,
  rowClassName,
  className,
}: DataTableProps<T>) {
  const selectableRows = selectable ? rows.filter((r) => (isRowSelectable ? isRowSelectable(r) : true)) : []
  const selectableKeys = selectableRows.map((r, i) => rowKey(r, i))
  const allChecked = selectableKeys.length > 0 && selectableKeys.every((k) => selectedKeys.includes(k))
  const someChecked = !allChecked && selectableKeys.some((k) => selectedKeys.includes(k))

  const toggleAll = () => {
    if (!onSelectedChange) return
    onSelectedChange(allChecked ? [] : selectableKeys)
  }

  const toggleOne = (key: string | number) => {
    if (!onSelectedChange) return
    onSelectedChange(
      selectedKeys.includes(key) ? selectedKeys.filter((k) => k !== key) : [...selectedKeys, key],
    )
  }

  const colCount = columns.length + (selectable ? 1 : 0)

  return (
    <div className={cn('w-full overflow-x-auto', className)}>
      <table className="w-full min-w-[640px] border-collapse text-[13px]">
        <thead>
          <tr className="border-b border-line bg-slate-50/80">
            {selectable ? (
              <th className="w-10 px-3 py-2.5">
                <input
                  type="checkbox"
                  aria-label="全选"
                  checked={allChecked}
                  ref={(el) => {
                    if (el) el.indeterminate = someChecked
                  }}
                  onChange={toggleAll}
                  disabled={!selectableKeys.length}
                  className="h-3.5 w-3.5 rounded border-line-strong accent-[color:var(--primary)]"
                />
              </th>
            ) : null}
            {columns.map((c) => (
              <th
                key={c.key}
                style={c.width ? { width: c.width } : undefined}
                className={cn(
                  'whitespace-nowrap px-3 py-2.5 text-xs font-medium text-slate-500',
                  ALIGN[c.align || 'left'],
                  c.headClassName,
                )}
              >
                {c.title}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {loading ? (
            <tr>
              <td colSpan={colCount} className="px-3 py-12 text-center text-[13px] text-slate-500">
                <span className="inline-flex items-center gap-2">
                  <Loader2 size={15} className="animate-spin text-primary" />
                  {loadingText}
                </span>
              </td>
            </tr>
          ) : rows.length === 0 ? (
            <tr>
              <td colSpan={colCount} className="px-3 py-10">
                {empty || <div className="text-center text-[13px] text-slate-400">暂无数据</div>}
              </td>
            </tr>
          ) : (
            rows.map((row, index) => {
              const key = rowKey(row, index)
              const selectableRow = isRowSelectable ? isRowSelectable(row) : true
              return (
                <tr
                  key={key}
                  onClick={onRowClick ? () => onRowClick(row) : undefined}
                  className={cn(
                    'border-b border-line last:border-0 transition-colors',
                    onRowClick && 'cursor-pointer',
                    'hover:bg-slate-50/70',
                    rowClassName?.(row),
                  )}
                >
                  {selectable ? (
                    <td className="px-3 py-2.5" onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        aria-label="选择行"
                        disabled={!selectableRow}
                        checked={selectedKeys.includes(key)}
                        onChange={() => toggleOne(key)}
                        className="h-3.5 w-3.5 rounded border-line-strong accent-[color:var(--primary)]"
                      />
                    </td>
                  ) : null}
                  {columns.map((c) => (
                    <td
                      key={c.key}
                      className={cn('px-3 py-2.5 align-middle text-slate-700', ALIGN[c.align || 'left'], c.className)}
                    >
                      {c.render(row, index)}
                    </td>
                  ))}
                </tr>
              )
            })
          )}
        </tbody>
      </table>
    </div>
  )
}

/** 详情类页面的键值表 */
export function KV({ label, children, className }: { label: ReactNode; children: ReactNode; className?: string }) {
  return (
    <div className={cn('flex gap-3 border-b border-line py-2 text-[13px] last:border-0', className)}>
      <div className="w-[110px] shrink-0 text-slate-500">{label}</div>
      <div className="min-w-0 flex-1 whitespace-pre-wrap break-words text-slate-800">{children}</div>
    </div>
  )
}
