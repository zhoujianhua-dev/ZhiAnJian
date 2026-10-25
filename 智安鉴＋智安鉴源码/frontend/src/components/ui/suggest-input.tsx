import { useEffect, useRef, useState } from 'react'
import { cn } from '@/lib/cn'
import { inputCls } from './field'

interface SuggestInputProps {
  value: string
  onChange: (v: string) => void
  /** 拉取候选值（已做防抖，可放心直接请求接口） */
  load: (keyword: string) => Promise<string[]>
  onPick?: (value: string) => void
  placeholder?: string
  className?: string
  inputClassName?: string
  disabled?: boolean
  max?: number
}

/** 带候选提示的输入框：单位名称 / 域名 / 漏洞名称等历史值复用 */
export function SuggestInput({
  value,
  onChange,
  load,
  onPick,
  placeholder,
  className,
  inputClassName,
  disabled,
  max = 8,
}: SuggestInputProps) {
  const [items, setItems] = useState<string[]>([])
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(-1)
  const wrapRef = useRef<HTMLDivElement>(null)
  const reqId = useRef(0)

  useEffect(() => {
    if (!open) return
    const id = ++reqId.current
    const timer = window.setTimeout(async () => {
      try {
        const list = await load(value.trim())
        if (id === reqId.current) {
          setItems(list.slice(0, max))
          setActive(-1)
        }
      } catch {
        if (id === reqId.current) setItems([])
      }
    }, 220)
    return () => window.clearTimeout(timer)
  }, [value, open, load, max])

  useEffect(() => {
    const onClickOutside = (e: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onClickOutside)
    return () => document.removeEventListener('mousedown', onClickOutside)
  }, [])

  function pick(item: string) {
    onChange(item)
    onPick?.(item)
    setOpen(false)
    setActive(-1)
  }

  return (
    <div ref={wrapRef} className={cn('relative', className)}>
      <input
        value={value}
        disabled={disabled}
        placeholder={placeholder}
        onChange={(e) => {
          onChange(e.target.value)
          setOpen(true)
        }}
        onFocus={() => setOpen(true)}
        onKeyDown={(e) => {
          if (!open || !items.length) return
          if (e.key === 'ArrowDown') {
            e.preventDefault()
            setActive((i) => (i + 1) % items.length)
          } else if (e.key === 'ArrowUp') {
            e.preventDefault()
            setActive((i) => (i <= 0 ? items.length - 1 : i - 1))
          } else if (e.key === 'Enter' && active >= 0) {
            e.preventDefault()
            pick(items[active])
          } else if (e.key === 'Escape') {
            setOpen(false)
          }
        }}
        className={cn(inputCls, inputClassName)}
      />
      {open && items.length > 0 ? (
        <ul className="absolute z-30 mt-1 max-h-56 w-full overflow-y-auto rounded-md border border-line bg-white py-1 shadow-pop">
          {items.map((item, i) => (
            <li key={item}>
              <button
                type="button"
                onMouseDown={(e) => e.preventDefault()}
                onClick={() => pick(item)}
                onMouseEnter={() => setActive(i)}
                className={cn(
                  'block w-full truncate px-3 py-1.5 text-left text-[13px]',
                  i === active ? 'bg-primary-soft text-primary' : 'text-slate-700 hover:bg-slate-50',
                )}
              >
                {item}
              </button>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  )
}
