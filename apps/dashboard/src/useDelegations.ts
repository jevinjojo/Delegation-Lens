import { useEffect, useState } from 'react'
import {
  API_BASE_URL,
  fetchDelegations,
  type Delegation,
  type DelegationCreatedEvent,
} from './api'

type Status = 'loading' | 'ready' | 'error'
type Connection = 'connecting' | 'live' | 'disconnected'

export function useDelegations() {
  const [delegations, setDelegations] = useState<Delegation[]>([])
  const [status, setStatus] = useState<Status>('loading')
  const [connection, setConnection] = useState<Connection>('connecting')
  const [error, setError] = useState<string | null>(null)

  // Effect 1: one-time initial load of whatever already exists.
  useEffect(() => {
    let cancelled = false
    fetchDelegations()
      .then((rows) => {
        if (cancelled) return
        setDelegations(rows)
        setStatus('ready')
      })
      .catch((err: unknown) => {
        if (cancelled) return
        setError(err instanceof Error ? err.message : 'Unknown error')
        setStatus('error')
      })
    return () => {
      cancelled = true // guard against setting state after unmount
    }
  }, [])

  // Effect 2: live stream. Opens an SSE connection and listens for "delegation" events.
  useEffect(() => {
    const source = new EventSource(`${API_BASE_URL}/api/v1/events`)

    source.onopen = () => setConnection('live')
    source.onerror = () => setConnection('disconnected') // browser auto-retries

    source.addEventListener('delegation', (event) => {
      try {
        const payload = JSON.parse(
          (event as MessageEvent).data,
        ) as DelegationCreatedEvent
        setDelegations((current) => {
          // Dedupe: ignore if we already have this id.
          if (current.some((d) => d.id === payload.delegation.id)) return current
          return [payload.delegation, ...current] // newest on top
        })
      } catch {
        // Malformed frame — ignore it, keep the stream alive.
      }
    })

    return () => source.close() // close the connection on unmount
  }, [])

  return { delegations, status, connection, error }
}