export const API = import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8080'

export interface Stats { active_delegations: number; tracked_accounts: number; canonical_blocks: number; reorgs: number; latest_block: number | null }
export interface HistoryRow { id: string; block_number: number; block_hash: string; authority: string; previous_implementation: string | null; new_implementation: string | null; tx_hash: string; canonical: number; applied_at: string; reverted_at: string | null }
export interface AccountDelegation { authority: string; implementation: string | null; block_number: number; block_hash: string; updated_at: string }
export interface ImplementationSummary { implementation: string; delegated_accounts: number; total_delegations: number; first_seen_block: number | null; last_seen_block: number | null }
export interface ReorgEvent { id: string; reverted_block_hash: string; block_number: number; depth: number; detected_at: string }
export interface Finding { rule_id: string; title: string; severity: string; confidence: string; evidence: string; explanation: string; remediation: string }
export interface Page<T> { items: T[]; next_cursor: number | null; limit: number }

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${API}${path}`)
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error((body as { error?: string }).error ?? `HTTP ${res.status}`)
  }
  return res.json() as Promise<T>
}

/** Fetches /metrics (Prometheus text) and parses simple `name value` gauges/counters. */
export async function getMetrics(): Promise<Record<string, number>> {
  const res = await fetch(`${API}/metrics`)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  const text = await res.text()
  const out: Record<string, number> = {}
  for (const line of text.split('\n')) {
    if (!line || line.startsWith('#')) continue
    const sp = line.indexOf(' ')
    if (sp < 0) continue
    const key = line.slice(0, sp)
    if (key.includes('{')) continue // skip histogram quantile series
    const val = Number(line.slice(sp + 1))
    if (!Number.isNaN(val)) out[key] = val
  }
  return out
}

export const getStats = () => get<Stats>('/api/v1/stats')
export const getChanges = (limit = 25) => get<Page<HistoryRow>>(`/api/v1/changes?limit=${limit}`)
export const getReorgs = (limit = 25) => get<ReorgEvent[]>(`/api/v1/reorgs?limit=${limit}`)
export const getAccount = (a: string) => get<AccountDelegation>(`/api/v1/accounts/${a}/delegation`)
export const getAccountHistory = (a: string, limit = 50) => get<Page<HistoryRow>>(`/api/v1/accounts/${a}/history?limit=${limit}`)
export const getImplementation = (a: string) => get<ImplementationSummary>(`/api/v1/implementations/${a}`)
export const getFindings = (a: string) => get<{ implementation: string; findings: Finding[]; note?: string }>(`/api/v1/implementations/${a}/findings`)
