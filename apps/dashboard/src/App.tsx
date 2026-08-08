import { useEffect, useState } from 'react'
import {
  API, getStats, getChanges,getMetrics, getReorgs, getAccount, getAccountHistory,
  getImplementation, getFindings,
  type Finding, type HistoryRow,
} from './api'
import { useAsync, type Async } from './hooks'

// ───────── helpers ─────────
const short = (s: string) => (s && s.length > 12 ? `${s.slice(0, 6)}…${s.slice(-4)}` : s)
const time = (s: string) => new Date(s).toLocaleString()

function AsyncBlock<T>({ state, children, empty }: { state: Async<T>; children: (d: T) => React.ReactNode; empty?: string }) {
  if (state.status === 'loading') return <p className="state">Loading…</p>
  if (state.status === 'error') return <p className="state state--error">Error: {state.error}</p>
  const d = state.data as T
  if (empty && Array.isArray(d) && (d as unknown[]).length === 0) return <p className="state">{empty}</p>
  return <>{children(d)}</>
}

const CanonBadge = ({ canonical }: { canonical: boolean }) =>
  <span className={`pill ${canonical ? 'pill--ok' : 'pill--bad'}`}>{canonical ? 'canonical' : 'reverted'}</span>
const StatusBadge = ({ status }: { status: string }) =>
  <span className={`pill ${status === 'cleared' ? 'pill--warn' : 'pill--ok'}`}>{status}</span>
const SevBadge = ({ s }: { s: string }) => <span className={`pill sev--${s.toLowerCase()}`}>{s}</span>
const ConfBadge = ({ c }: { c: string }) => <span className={`pill conf--${c.toLowerCase()}`}>{c}</span>

// ───────── feed normalization ─────────
interface FeedItem { key: string; authority: string; implementation: string | null; block_number: number; tx_hash: string; status: string; canonical: boolean; when: string }
const rowToFeed = (r: HistoryRow): FeedItem => ({ key: r.id, authority: r.authority, implementation: r.new_implementation, block_number: r.block_number, tx_hash: r.tx_hash, status: r.new_implementation ? 'active' : 'cleared', canonical: r.canonical === 1, when: r.applied_at })

function useLiveFeed() {
  const [items, setItems] = useState<FeedItem[]>([])
  const [conn, setConn] = useState<'connecting' | 'live' | 'down'>('connecting')
  useEffect(() => {
    let cancelled = false
    getChanges(25).then((p) => { if (!cancelled) setItems(p.items.map(rowToFeed)) }).catch(() => {})
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
      } catch { /* ignore malformed */ }
    })
    return () => { cancelled = true; es.close() }
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
      <div className="grid">
        <Stat label="Active delegations" value={s.active_delegations} />
        <Stat label="Tracked accounts" value={s.tracked_accounts} />
        <Stat label="Canonical blocks" value={s.canonical_blocks} />
        <Stat label="Reorgs" value={s.reorgs} warn={s.reorgs > 0} />
        <Stat label="Latest block" value={s.latest_block ?? '—'} />
      </div>
    )}</AsyncBlock>
  )
}
const Stat = ({ label, value, warn }: { label: string; value: React.ReactNode; warn?: boolean }) =>
  <div className={`card ${warn ? 'card--warn' : ''}`}><div className="card__value">{value}</div><div className="card__label">{label}</div></div>

function LiveFeed() {
  const { items, conn } = useLiveFeed()
  return (
    <>
      <div className="row"><h2>Live delegation feed</h2><span className={`badge badge--${conn}`}>{conn}</span></div>
      {items.length === 0 ? <p className="state">Waiting for delegations…</p> : (
        <div className="tablewrap"><table className="table"><thead><tr>
          <th>Account</th><th>Implementation</th><th>Block</th><th>Status</th><th>State</th><th>When</th>
        </tr></thead><tbody>
          {items.map((i) => (
            <tr key={i.key}>
              <td><a href={`#/account/${i.authority}`}>{short(i.authority)}</a></td>
              <td>{i.implementation ? <a href={`#/implementation/${i.implementation}`}>{short(i.implementation)}</a> : <em>cleared</em>}</td>
              <td>{i.block_number}</td>
              <td><StatusBadge status={i.status} /></td>
              <td><CanonBadge canonical={i.canonical} /></td>
              <td>{time(i.when)}</td>
            </tr>
          ))}
        </tbody></table></div>
      )}
    </>
  )
}

function Search({ kind }: { kind: 'account' | 'implementation' }) {
  const [v, setV] = useState('')
  return (
    <form className="row" onSubmit={(e) => { e.preventDefault(); if (v) window.location.hash = `#/${kind}/${v.trim()}` }}>
      <input className="input" placeholder={`0x… ${kind} address`} value={v} onChange={(e) => setV(e.target.value)} />
      <button className="btn" type="submit">Look up</button>
    </form>
  )
}

function AccountView({ address }: { address?: string }) {
  if (!address) return <><h2>Account</h2><Search kind="account" /></>
  const del = useAsync(() => getAccount(address), [address])
  const hist = useAsync(() => getAccountHistory(address), [address])
  return (
    <>
      <h2>Account {short(address)}</h2><Search kind="account" />
      <h3>Current delegation</h3>
      {del.status === 'error' ? <p className="state">No active delegation for this account.</p> :
        <AsyncBlock state={del}>{(d) => (
          <div className="grid">
            <Stat label="Implementation" value={d.implementation ? short(d.implementation) : 'cleared'} />
            <Stat label="Set at block" value={d.block_number} />
            <Stat label="Updated" value={time(d.updated_at)} />
          </div>
        )}</AsyncBlock>}
      <h3>History</h3>
      <AsyncBlock state={hist} empty="No history.">{(p) => <HistoryTable rows={p.items} />}</AsyncBlock>
    </>
  )
}

function HistoryTable({ rows }: { rows: HistoryRow[] }) {
  if (rows.length === 0) return <p className="state">No history.</p>
  return (
    <div className="tablewrap"><table className="table"><thead><tr>
      <th>Block</th><th>From</th><th>To</th><th>Tx</th><th>State</th><th>When</th>
    </tr></thead><tbody>
      {rows.map((r) => (
        <tr key={r.id} className={r.canonical === 1 ? '' : 'row--reverted'}>
          <td>{r.block_number}</td>
          <td>{r.previous_implementation ? short(r.previous_implementation) : <em>none</em>}</td>
          <td>{r.new_implementation ? short(r.new_implementation) : <em>cleared</em>}</td>
          <td title={r.tx_hash}>{short(r.tx_hash)}</td>
          <td><CanonBadge canonical={r.canonical === 1} /></td>
          <td>{time(r.applied_at)}</td>
        </tr>
      ))}
    </tbody></table></div>
  )
}

function ImplementationView({ address }: { address?: string }) {
  if (!address) return <><h2>Implementation</h2><Search kind="implementation" /></>
  const sum = useAsync(() => getImplementation(address), [address])
  const fin = useAsync(() => getFindings(address), [address])
  return (
    <>
      <h2>Implementation {short(address)}</h2><Search kind="implementation" />
      {sum.status === 'error' ? <p className="state">Not seen yet as a delegation target.</p> :
        <AsyncBlock state={sum}>{(s) => (
          <div className="grid">
            <Stat label="Delegated accounts" value={s.delegated_accounts} />
            <Stat label="Total delegations" value={s.total_delegations} />
            <Stat label="First seen block" value={s.first_seen_block ?? '—'} />
            <Stat label="Last seen block" value={s.last_seen_block ?? '—'} />
          </div>
        )}</AsyncBlock>}
      <h3>Security findings</h3>
      <p className="disclaimer">Findings are static heuristics, not proof of exploitability. Confidence is shown on every finding.</p>
      <AsyncBlock state={fin}>{(f) => f.findings.length === 0
        ? <p className="state">{f.note ?? 'No findings.'}</p>
        : <div>{f.findings.map((x) => <FindingCard key={x.rule_id} f={x} />)}</div>}
      </AsyncBlock>
    </>
  )
}

const FindingCard = ({ f }: { f: Finding }) => (
  <div className="finding">
    <div className="row"><strong>{f.rule_id} — {f.title}</strong><span><SevBadge s={f.severity} /> <ConfBadge c={f.confidence} /></span></div>
    <p><b>Evidence:</b> {f.evidence}</p>
    <p>{f.explanation}</p>
    <p><b>Remediation:</b> {f.remediation}</p>
  </div>
)

function ReorgTimeline() {
  const rr = useAsync(() => getReorgs(50), [])
  return (
    <>
      <h2>Reorg timeline</h2>
      <AsyncBlock state={rr} empty="No reorgs detected — the canonical chain has been stable.">{(items) => (
        <ol className="timeline">
          {items.map((e) => (
            <li key={e.id}>
              <span className="pill pill--bad">reverted</span> block <b>{e.block_number}</b> ({short(e.reverted_block_hash)})
              · depth {e.depth} · {time(e.detected_at)}
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
      <div className="row"><h2>System health</h2><span className={`badge badge--${conn}`}>SSE {conn}</span></div>

      <AsyncBlock state={stats}>{(s) => (
        <div className="grid">
          <Stat label="Latest canonical block" value={s.latest_block ?? '—'} />
          <Stat label="Canonical blocks stored" value={s.canonical_blocks} />
          <Stat label="Active delegations" value={s.active_delegations} />
          <Stat label="Reorgs handled" value={s.reorgs} warn={s.reorgs > 0} />
        </div>
      )}</AsyncBlock>

      <h3>Ingestion</h3>
      <AsyncBlock state={metrics}>{(m) => (
        <div className="grid">
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
  ['implementation', 'Implementation'], ['reorgs', 'Reorgs'], ['health', 'Health'],
] as const

export default function App() {
  const { view, param } = useRoute()
  const [theme, toggleTheme] = useTheme()
  return (
    <div className="app">
      <header className="app__header">
        <div>
          <h1>DelegationLens</h1>
          <div className="card__label">Reorg-aware EIP-7702 delegation intelligence</div>
        </div>
        <nav className="nav">{NAV.map(([h, label]) => (
          <a key={h} href={`#/${h}`} className={`nav__link ${view === (h || 'overview') ? 'active' : ''}`}>{label}</a>
        ))}</nav>
        <button className="theme-toggle" onClick={toggleTheme} aria-label="Toggle theme">
          {theme === 'light' ? '🌙' : '☀️'}
        </button>
      </header>
      <main>
        {view === 'overview' && <Overview />}
        {view === 'feed' && <LiveFeed />}
        {view === 'account' && <AccountView address={param} />}
        {view === 'implementation' && <ImplementationView address={param} />}
        {view === 'reorgs' && <ReorgTimeline />}
        {view === 'health' && <SystemHealth />}
      </main>
    </div>
  )
}