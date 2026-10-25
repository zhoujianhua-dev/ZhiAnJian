import { forwardRef, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type TextareaHTMLAttributes } from 'react'
import { ChevronDown } from 'lucide-react'
import { cn } from '@/lib/cn'

export const inputCls =
  'h-9 w-full rounded-md border border-line-strong bg-white px-3 text-[13px] text-slate-800 placeholder:text-slate-400 ' +
  'outline-none transition-colors focus:border-primary focus:ring-2 focus:ring-primary-line ' +
  'disabled:cursor-not-allowed disabled:bg-slate-50 disabled:text-slate-400'

export const textareaCls =
  'w-full rounded-md border border-line-strong bg-white px-3 py-2 text-[13px] leading-6 text-slate-800 ' +
  'placeholder:text-slate-400 outline-none transition-colors focus:border-primary focus:ring-2 focus:ring-primary-line ' +
  'disabled:cursor-not-allowed disabled:bg-slate-50 disabled:text-slate-400 resize-y'

interface FieldProps {
  label?: ReactNode
  required?: boolean
  hint?: ReactNode
  error?: ReactNode
  className?: string
  children: ReactNode
}

export function Field({ label, required, hint, error, className, children }: FieldProps) {
  return (
    <div className={cn('flex min-w-0 flex-col gap-1.5', className)}>
      {label ? (
        <label className="text-xs font-medium text-slate-600">
          {label}
          {required ? <span className="ml-0.5 text-red-500">*</span> : null}
        </label>
      ) : null}
      {children}
      {error ? <p className="text-xs text-red-600">{error}</p> : null}
      {!error && hint ? <p className="text-xs text-slate-400">{hint}</p> : null}
    </div>
  )
}

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(function Input(
  { className, ...rest },
  ref,
) {
  return <input ref={ref} className={cn(inputCls, className)} {...rest} />
})

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement>>(
  function Textarea({ className, rows = 3, ...rest }, ref) {
    return <textarea ref={ref} rows={rows} className={cn(textareaCls, className)} {...rest} />
  },
)

export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(function Select(
  { className, children, ...rest },
  ref,
) {
  return (
    <div className="relative">
      <select
        ref={ref}
        className={cn(inputCls, 'cursor-pointer appearance-none pr-8', className)}
        {...rest}
      >
        {children}
      </select>
      <ChevronDown size={14} className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
    </div>
  )
})

interface CheckboxProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'type'> {
  label?: ReactNode
}

export function Checkbox({ label, className, ...rest }: CheckboxProps) {
  return (
    <label className={cn('inline-flex cursor-pointer select-none items-center gap-2 text-[13px] text-slate-700', className)}>
      <input
        type="checkbox"
        className="h-3.5 w-3.5 rounded border-line-strong text-primary accent-[color:var(--primary)] focus:ring-primary-line"
        {...rest}
      />
      {label}
    </label>
  )
}

interface SwitchProps {
  checked: boolean
  onChange: (v: boolean) => void
  label?: ReactNode
  disabled?: boolean
}

export function Switch({ checked, onChange, label, disabled }: SwitchProps) {
  return (
    <label className={cn('inline-flex select-none items-center gap-2 text-[13px] text-slate-700', disabled ? 'cursor-not-allowed opacity-60' : 'cursor-pointer')}>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={cn(
          'relative h-[20px] w-[36px] shrink-0 rounded-full transition-colors',
          checked ? 'bg-primary' : 'bg-slate-300',
        )}
      >
        <span
          className={cn(
            'absolute top-[2px] h-4 w-4 rounded-full bg-white transition-all',
            checked ? 'left-[18px]' : 'left-[2px]',
          )}
        />
      </button>
      {label}
    </label>
  )
}
