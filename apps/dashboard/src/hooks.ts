import { useEffect, useState } from 'react'

export type Async<T> = { status: 'loading' | 'ready' | 'error'; data?: T; error?: string }

export function useAsync<T>(fn: () => Promise<T>, deps: unknown[] = []): Async<T> {
  const [state, setState] = useState<Async<T>>({ status: 'loading' })
  useEffect(() => {
    let cancelled = false
    setState({ status: 'loading' })
    fn()
      .then((data) => { if (!cancelled) setState({ status: 'ready', data }) })
      .catch((e: unknown) => { if (!cancelled) setState({ status: 'error', error: e instanceof Error ? e.message : String(e) }) })
    return () => { cancelled = true }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)
  return state
}