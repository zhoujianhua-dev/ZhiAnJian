import { useCallback, useEffect, useRef, useState } from 'react'

interface QueryState<T> {
  data: T | null
  loading: boolean
  error: string | null
}

/**
 * 极简请求 hook：自动处理 loading / error / 卸载后 setState。
 * fn 需用 useCallback 包裹，避免每次渲染都重新请求。
 */
export function useQuery<T>(fn: () => Promise<T>, deps: unknown[] = []) {
  const [state, setState] = useState<QueryState<T>>({ data: null, loading: true, error: null })
  const seq = useRef(0)
  const mounted = useRef(true)

  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])

  const run = useCallback(
    async (silent = false) => {
      const id = ++seq.current
      if (!silent) setState((s) => ({ ...s, loading: true, error: null }))
      try {
        const data = await fn()
        if (id === seq.current && mounted.current) setState({ data, loading: false, error: null })
      } catch (e) {
        if (id === seq.current && mounted.current) {
          setState((s) => ({ ...s, loading: false, error: e instanceof Error ? e.message : '请求失败' }))
        }
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    deps,
  )

  useEffect(() => {
    void run()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [run])

  return {
    ...state,
    reload: () => run(),
    refresh: () => run(true),
    setData: (data: T) => setState((s) => ({ ...s, data })),
  }
}
