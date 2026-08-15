import { useEffect, useState } from 'react'
import {
  API, getStats, getChanges, getMetrics, getReorgs, getAccount, getAccountHistory,
  getImplementation, getFindings, getAlerts,
  type Finding, type HistoryRow,
} from './api'
import { useAsync, type Async } from './hooks'

// ───────── helpers ─────────
const short = (s: string) => (s && s.length > 12 ? `${s.slice(0, 6)}…${s.slice(-4)}` : s)
const time = (s: string) => new Date(s).toLocaleString()

const copyToClipboard = async (value: string) => {
  try {
    await navigator.clipboard.writeText(value)
  } catch {
    // ignore copy failures in unsupported browsers or restricted contexts
  }
}

function AsyncBlock<T>({ state, children, empty }: { state: Async<T>; children: (d: T) => React.ReactNode; empty?: string }) {
  if (state.status === 'loading') return <div className="state state--loading">Loading dataset…</div>
  if (state.status === 'error') return <div className="state state--error">Error: {state.error}</div>
  const d = state.data as T
  if (empty && Array.isArray(d) && (d as unknown[]).length === 0) return <div className="state">{empty}</div>
  return <>{children(d)}</>
}

const AddressCell = ({ value, route }: { value: string; route: string }) => (
  <div className="address-cell">
    <a href={route} className="address-link" title={value}>{short(value)}</a>
    <button
      type="button"
      className="copy-button"
      onClick={() => copyToClipboard(value)}
      title={`Copy ${value}`}
      aria-label={`Copy ${value}`}
    >
      Copy
    </button>
  </div>
)

const CanonBadge = ({ canonical, cleared = false }: { canonical: boolean; cleared?: boolean }) => (
  <span className={`status-pill ${canonical ? 'status-pill--ok' : cleared ? 'status-pill--cleared' : 'status-pill--reverted'}`}>
    {canonical ? 'canonical' : cleared ? 'cleared' : 'reverted'}
  </span>
)

const StatusBadge = ({ status }: { status: string }) => (
  <span className={`status-pill ${status === 'cleared' ? 'status-pill--cleared' : status === 'active' ? 'status-pill--ok' : 'status-pill--reverted'}`}>
    {status}
  </span>
)

const SevBadge = ({ s }: { s: string }) => <span className={`status-pill sev--${s.toLowerCase()}`}>{s}</span>
const ConfBadge = ({ c }: { c: string }) => <span className={`status-pill conf--${c.toLowerCase()}`}>{c}</span>
const ConnectionBadge = ({ state }: { state: 'connecting' | 'live' | 'down' }) => (
  <span className={`badge badge--${state}`}>{state === 'live' ? 'Live' : state === 'connecting' ? 'Connecting' : 'Down'}</span>
)

// ───────── feed normalization ─────────
interface FeedItem { key: string; authority: string; implementation: string | null; block_number: number; tx_hash: string; status: string; canonical: boolean; when: string }
const rowToFeed = (r: HistoryRow): FeedItem => ({
  key: r.id,
  authority: r.authority,
  implementation: r.new_implementation,
  block_number: r.block_number,
  tx_hash: r.tx_hash,
  status: r.new_implementation ? 'active' : 'cleared',
  canonical: r.canonical === 1,
  when: r.applied_at,
})

function useLiveFeed() {
  const [items, setItems] = useState<FeedItem[]>([])
  const [conn, setConn] = useState<'connecting' | 'live' | 'down'>('connecting')
  useEffect(() => {
    let cancelled = false
    getChanges(25)
      .then((p) => {
        if (!cancelled) setItems(p.items.map(rowToFeed))
      })
      .catch(() => {})

    const es = new EventSource(`${API}/api/v1/events`)
    es.onopen = () => setConn('live')
    es.onerror = () => setConn('down')
    es.addEventListener('delegation', (e) => {
      try {
        const d = JSON.parse((e as MessageEvent).data).delegation
        const item: FeedItem = {
          key: `${d.transaction_hash}-${d.account}-${Math.random()}`,
          authority: d.account,
          implementation: d.status === 'cleared' ? null : d.implementation,
          block_number: Number(d.block_number),
          tx_hash: d.transaction_hash,
          status: d.status,
          canonical: true,
          when: d.created_at,
        }
        setItems((cur) => [item, ...cur].slice(0, 100))
      } catch {
        // ignore malformed
      }
    })
    return () => {
      cancelled = true
      es.close()
    }
  }, [])
  return { items, conn }
}

// ───────── routing ─────────
function useRoute() {
  const [hash, setHash] = useState(window.location.hash || '#/')
  useEffect(() => {
    const h = () => setHash(window.location.hash || '#/')
    window.addEventListener('hashchange', h)
    return () => window.removeEventListener('hashchange', h)
  }, [])
  const clean = hash.replace(/^#\/?/, '')
  const [view, param] = clean.split('/')
  return { view: view || 'overview', param: param ? decodeURIComponent(param) : undefined }
}

function useTheme(): [string, () => void] {
  const [theme, setTheme] = useState<string>(() => localStorage.getItem('dl-theme') || 'light')
  useEffect(() => {
    document.documentElement.dataset.theme = theme
    localStorage.setItem('dl-theme', theme)
  }, [theme])
  return [theme, () => setTheme((t) => (t === 'light' ? 'dark' : 'light'))]
}

// ───────── views ─────────
function Overview() {
  const stats = useAsync(getStats, [])
  return (
    <AsyncBlock state={stats}>{(s) => (
      <div className="stat-grid">
        <Stat label="Active delegations" value={s.active_delegations} />
        <Stat label="Tracked accounts" value={s.tracked_accounts} />
        <Stat label="Canonical blocks" value={s.canonical_blocks} />
        <Stat label="Reorgs" value={s.reorgs} warn={s.reorgs > 0} />
        <Stat label="Latest block" value={s.latest_block ?? '—'} />
        <Stat label="Analyzed implementations" value={s.analyzed_implementations} />
        <Stat label="High-risk accounts" value={s.high_risk_accounts} warn={s.high_risk_accounts > 0} />
      </div>
    )}</AsyncBlock>
  )
}

const Stat = ({ label, value, warn }: { label: string; value: React.ReactNode; warn?: boolean }) => (
  <div className={`stat-card ${warn ? 'stat-card--warn' : ''}`}>
    <div className="stat-card__spark" aria-hidden="true" />
    <div className="stat-card__label">{label}</div>
    <div className="stat-card__value">{value}</div>
  </div>
)

function LiveFeed() {
  const { items, conn } = useLiveFeed()
  return (
    <>
      <div className="section-header">
        <h2>Live delegation feed</h2>
        <ConnectionBadge state={conn} />
      </div>
      {items.length === 0 ? <div className="state">Waiting for delegations…</div> : (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Account</th>
                <th>Implementation</th>
                <th>Block</th>
                <th>Status</th>
                <th>State</th>
                <th>When</th>
              </tr>
            </thead>
            <tbody>
              {items.map((i) => (
                <tr key={i.key} className="live-row">
                  <td><AddressCell value={i.authority} route={`#/account/${i.authority}`} /></td>
                  <td>
                    {i.implementation ? (
                      <AddressCell value={i.implementation} route={`#/implementation/${i.implementation}`} />
                    ) : (
                      <span className="muted-copy">cleared</span>
                    )}
                  </td>
                  <td>{i.block_number}</td>
                  <td><StatusBadge status={i.status} /></td>
                  <td><CanonBadge canonical={i.canonical} cleared={i.status === 'cleared'} /></td>
                  <td>{time(i.when)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}

function Search({ kind }: { kind: 'account' | 'implementation' }) {
  const [v, setV] = useState('')
  return (
    <form
      className="search-row"
      onSubmit={(e) => {
        e.preventDefault()
        if (v) window.location.hash = `#/${kind}/${v.trim()}`
      }}
    >
      <input className="input" placeholder={`0x… ${kind} address`} value={v} onChange={(e) => setV(e.target.value)} />
      <button className="btn btn--primary" type="submit">Look up</button>
    </form>
  )
}

function AccountView({ address }: { address?: string }) {
  if (!address) return <><h2>Account</h2><Search kind="account" /></>
  const del = useAsync(() => getAccount(address), [address])
  const hist = useAsync(() => getAccountHistory(address), [address])
  return (
    <>
      <div className="section-header section-header--tight">
        <h2>Account {short(address)}</h2>
      </div>
      <Search kind="account" />
      <h3>Current delegation</h3>
      {del.status === 'error' ? <div className="state">No active delegation for this account.</div> : (
        <AsyncBlock state={del}>{(d) => (
          <div className="stat-grid">
            <Stat label="Implementation" value={d.implementation ? <AddressCell value={d.implementation} route={`#/implementation/${d.implementation}`} /> : 'cleared'} />
            <Stat label="Set at block" value={d.block_number} />
            <Stat label="Updated" value={time(d.updated_at)} />
          </div>
        )}</AsyncBlock>
      )}
      <h3>History</h3>
      <AsyncBlock state={hist} empty="No history.">{(p) => <HistoryTable rows={p.items} />}</AsyncBlock>
    </>
  )
}

function HistoryTable({ rows }: { rows: HistoryRow[] }) {
  if (rows.length === 0) return <div className="state">No history.</div>
  return (
    <div className="table-wrap">
      <table className="data-table">
        <thead>
          <tr>
            <th>Block</th>
            <th>From</th>
            <th>To</th>
            <th>Nonce</th>
            <th>Tx</th>
            <th>State</th>
            <th>When</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id} className={r.canonical === 1 ? '' : 'row--reverted'}>
              <td>{r.block_number}</td>
              <td>{r.previous_implementation ? <AddressCell value={r.previous_implementation} route={`#/implementation/${r.previous_implementation}`} /> : <span className="muted-copy">none</span>}</td>
              <td>{r.new_implementation ? <AddressCell value={r.new_implementation} route={`#/implementation/${r.new_implementation}`} /> : <span className="muted-copy">cleared</span>}</td>
              <td>{r.nonce ?? '—'}</td>
              <td title={r.tx_hash} className="mono-copy">{short(r.tx_hash)}</td>
              <td><CanonBadge canonical={r.canonical === 1} cleared={r.new_implementation === null} /></td>
              <td>{time(r.applied_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function ImplementationView({ address }: { address?: string }) {
  if (!address) return <><h2>Implementation</h2><Search kind="implementation" /></>
  const sum = useAsync(() => getImplementation(address), [address])
  const fin = useAsync(() => getFindings(address), [address])
  return (
    <>
      <div className="section-header section-header--tight">
        <h2>Implementation {short(address)}</h2>
      </div>
      <Search kind="implementation" />
      {sum.status === 'error' ? <div className="state">Not seen yet as a delegation target.</div> : (
        <AsyncBlock state={sum}>{(s) => (
          <div className="stat-grid">
            <Stat label="Delegated accounts" value={s.delegated_accounts} />
            <Stat label="Total delegations" value={s.total_delegations} />
            <Stat label="First seen block" value={s.first_seen_block ?? '—'} />
            <Stat label="Last seen block" value={s.last_seen_block ?? '—'} />
            <Stat label="Source" value={s.source_available ? 'verified' : 'bytecode-only'} />
            <Stat label="Bytecode hash" value={s.bytecode_hash ? short(s.bytecode_hash) : '—'} />
          </div>
        )}</AsyncBlock>
      )}
      <h3>Security findings</h3>
      <p className="disclaimer">Static heuristics, not proof of exploitability. Bytecode-only analysis is Heuristic confidence.</p>
      <AsyncBlock state={fin}>{(f) => f.findings.length === 0 ? <div className="state">No findings for this implementation.</div> : <div>{f.findings.map((x, i) => <FindingCard key={i} f={x} />)}</div>}</AsyncBlock>
    </>
  )
}

function AlertsView() {
  const st = useAsync(getAlerts, [])
  return (
    <>
      <div className="section-header">
        <h2>Active alerts</h2>
      </div>
      <p className="disclaimer">Accounts currently delegated to an implementation with a High/Critical finding. Follows canonical state — reverted delegations drop off automatically.</p>
      <AsyncBlock state={st} empty="No high-risk delegations right now.">{(items) => (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Account</th>
                <th>Implementation</th>
                <th>Rule</th>
                <th>Severity</th>
                <th>Block</th>
              </tr>
            </thead>
            <tbody>
              {items.map((a, i) => (
                <tr key={i}>
                  <td><AddressCell value={a.authority} route={`#/account/${a.authority}`} /></td>
                  <td><AddressCell value={a.implementation} route={`#/implementation/${a.implementation}`} /></td>
                  <td>{a.rule_id}</td>
                  <td><SevBadge s={a.severity} /></td>
                  <td>{a.block_number}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}</AsyncBlock>
    </>
  )
}

const FindingCard = ({ f }: { f: Finding }) => (
  <div className="finding-card">
    <div className="finding-card__head">
      <div className="finding-card__title">{f.rule_id} — {f.title}</div>
      <div className="finding-card__badges">
        <SevBadge s={f.severity} />
        <ConfBadge c={f.confidence} />
      </div>
    </div>
    <p><span className="muted-label">Evidence:</span> {f.evidence}</p>
    <p>{f.explanation}</p>
    <p><span className="muted-label">Remediation:</span> {f.remediation}</p>
  </div>
)

function ReorgTimeline() {
  const rr = useAsync(() => getReorgs(50), [])
  return (
    <>
      <div className="section-header">
        <h2>Reorg timeline</h2>
      </div>
      <AsyncBlock state={rr} empty="No reorgs detected — the canonical chain has been stable.">{(items) => (
        <ol className="timeline">
          {items.map((e) => (
            <li key={e.id} className="timeline-item">
              <span className="status-pill status-pill--reverted">reverted</span>
              <div>
                <span>block <strong>{e.block_number}</strong></span>
                <span className="mono-copy">({short(e.reverted_block_hash)})</span>
                <span> · depth {e.depth}</span>
                <span> · {time(e.detected_at)}</span>
              </div>
            </li>
          ))}
        </ol>
      )}</AsyncBlock>
    </>
  )
}

function SystemHealth() {
  const stats = useAsync(getStats, [])
  const metrics = useAsync(getMetrics, [])
  const [conn, setConn] = useState<'connecting' | 'live' | 'down'>('connecting')
  useEffect(() => {
    const es = new EventSource(`${API}/api/v1/events`)
    es.onopen = () => setConn('live')
    es.onerror = () => setConn('down')
    return () => es.close()
  }, [])

  return (
    <>
      <div className="section-header">
        <h2>System health</h2>
        <ConnectionBadge state={conn} />
      </div>

      <AsyncBlock state={stats}>{(s) => (
        <div className="stat-grid">
          <Stat label="Latest canonical block" value={s.latest_block ?? '—'} />
          <Stat label="Canonical blocks stored" value={s.canonical_blocks} />
          <Stat label="Active delegations" value={s.active_delegations} />
          <Stat label="Reorgs handled" value={s.reorgs} warn={s.reorgs > 0} />
        </div>
      )}</AsyncBlock>

      <h3>Ingestion</h3>
      <AsyncBlock state={metrics}>{(m) => (
        <div className="stat-grid">
          <Stat label="Ingestion lag (blocks)" value={m.ingestion_lag_blocks ?? 0} warn={(m.ingestion_lag_blocks ?? 0) > 25} />
          <Stat label="Blocks processed" value={m.blocks_processed_total ?? 0} />
          <Stat label="Authorizations detected" value={m.authorizations_detected_total ?? 0} />
          <Stat label="RPC errors" value={m.rpc_errors_total ?? 0} warn={(m.rpc_errors_total ?? 0) > 0} />
          <Stat label="SSE clients" value={m.sse_clients ?? 0} />
        </div>
      )}</AsyncBlock>
    </>
  )
}

const NAV = [
  ['', 'Overview'], ['feed', 'Live feed'], ['account', 'Account'],
  ['implementation', 'Implementation'], ['alerts', 'Alerts'], ['reorgs', 'Reorgs'], ['health', 'Health'],
] as const

export default function App() {
  const { view, param } = useRoute()
  const [theme, toggleTheme] = useTheme()
  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="brand-block">
          <div className="brand-mark" aria-hidden="true">
            <svg viewBox="0 0 24 24" role="img" aria-label="DelegationLens brand icon">
              <path d="M12 2.8 18.8 5v6.3c0 4.2-2.7 8.1-6.8 10.4-4.1-2.3-6.8-6.2-6.8-10.4V5L12 2.8Zm0 4.2 3.5 1.4v4.3c0 2.9-1.8 5.7-3.5 7-1.7-1.3-3.5-4.1-3.5-7V8.4L12 7Z" />
              <path d="M12 8.5 14.2 9.4v3.2c0 1.8-1 3.5-2.2 4.4-1.2-.9-2.2-2.6-2.2-4.4V9.4L12 8.5Z" />
            </svg>
          </div>
          <div className="brand-copy">
            <h1>DelegationLens</h1>
            <div className="eyebrow">
              <span className="eyebrow-icon" aria-hidden="true">◌</span>
              Reorg-aware EIP-7702 delegation intelligence
            </div>
          </div>
        </div>

        <nav className="nav" aria-label="Main navigation">
          {NAV.map(([h, label]) => (
            <a key={h} href={`#/${h}`} className={`nav__link ${view === (h || 'overview') ? 'active' : ''}`}>
              {label}
            </a>
          ))}
        </nav>

        <button className="theme-toggle" onClick={toggleTheme} aria-label="Toggle theme">
          {theme === 'light' ? '🌙' : '☀️'}
        </button>
      </header>

      <main className="page-shell">
        {view === 'overview' && <Overview />}
        {view === 'feed' && <LiveFeed />}
        {view === 'account' && <AccountView address={param} />}
        {view === 'implementation' && <ImplementationView address={param} />}
        {view === 'alerts' && <AlertsView />}
        {view === 'reorgs' && <ReorgTimeline />}
        {view === 'health' && <SystemHealth />}
      </main>
    </div>
  )
}