import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react'
import { AlertTriangle } from 'lucide-react'
import { Button } from './button'
import { Modal } from './modal'

export interface ConfirmOptions {
  title?: string
  message: ReactNode
  confirmText?: string
  cancelText?: string
  danger?: boolean
}

type ConfirmFn = (options: ConfirmOptions | string) => Promise<boolean>

const ConfirmContext = createContext<ConfirmFn | null>(null)

export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<{ options: ConfirmOptions; resolve: (v: boolean) => void } | null>(null)

  const confirm = useCallback<ConfirmFn>((input) => {
    const options = typeof input === 'string' ? { message: input } : input
    return new Promise<boolean>((resolve) => setState({ options, resolve }))
  }, [])

  const close = (result: boolean) => {
    setState((s) => {
      s?.resolve(result)
      return null
    })
  }

  const value = useMemo(() => confirm, [confirm])

  return (
    <ConfirmContext.Provider value={value}>
      {children}
      <Modal
        open={!!state}
        onClose={() => close(false)}
        title={state?.options.title || '操作确认'}
        size="sm"
        footer={
          <>
            <Button onClick={() => close(false)}>{state?.options.cancelText || '取消'}</Button>
            <Button
              variant={state?.options.danger === false ? 'primary' : 'danger'}
              onClick={() => close(true)}
            >
              {state?.options.confirmText || '确定'}
            </Button>
          </>
        }
      >
        <div className="flex items-start gap-3">
          <span className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-red-200 bg-red-50 text-red-600">
            <AlertTriangle size={17} />
          </span>
          <div className="pt-1 text-[13.5px] leading-6 text-slate-700">{state?.options.message}</div>
        </div>
      </Modal>
    </ConfirmContext.Provider>
  )
}

export function useConfirm() {
  const ctx = useContext(ConfirmContext)
  if (!ctx) throw new Error('useConfirm 必须在 ConfirmProvider 内使用')
  return ctx
}
