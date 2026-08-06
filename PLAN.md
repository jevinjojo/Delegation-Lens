# DelegationLens — Project Plan

> Reorg-aware EIP-7702 delegation intelligence and security analysis platform.

## Project Philosophy & Guardrails

**Timeline**

- Part-time: 10–12 weeks
- Full-time: 5–7 weeks
- While interview-prepping: ~60–90 min/weekday + one 3–4 hour weekend block. This project must not replace interview prep.

**V1 Definition of Done**

> V1 is complete when DelegationLens can ingest EIP-7702 transactions from recorded fixtures and a live Ethereum RPC endpoint, decode authorization tuples, track each account’s canonical delegation history across shallow reorgs, analyze delegated implementations using at least three evidence-based security rules, persist the results, expose them through an Axum API, and update a live React dashboard with delegation events, risk findings, and system health.

**Scope Protection**

- Anything not required by the Definition of Done goes into `V2_BACKLOG.md`. No exceptions.
- Scope for this build stops at the **live dashboard**. reth ExEx integration is explicitly V2.

**Out of scope for V1 (put in V2_BACKLOG.md)**

- reth ExEx integration
- Multi-chain operational indexing
- Mainnet historical backfill
- Universal symbolic execution / decompiler
- Browser extension / mobile app
- ML-based threat detection
- Automated transaction blocking
- ERC-4337 bundler integration
- Implementation reputation network
- Team accounts / RBAC / multi-tenant

## Naming

- Project: **DelegationLens** (avoids reusing "Guard" from SolGuard)
- Repo: `delegation-lens`

## Final V1 Architecture

```text
Recorded fixtures / Ethereum RPC
                |
                v
        RPC Chain Observer
                |
                v
     EIP-7702 Transaction Decoder
                |
                v
       Canonical Block Processor
                |
          +-----+------+
          |            |
          v            v
 Delegation Tracker  Reorg Journal
          |            |
          +-----+------+
                |
                v
     Implementation Resolver
                |
                v
       Security Analyzer
                |
                v
       Risk / Policy Engine
                |
                v
          SQLite Database
                |
        +-------+--------+
        |                |
        v                v
    Axum API       Prometheus Metrics
        |
        v
    SSE live stream
        |
        v
React + Vite Dashboard
```

## V1 Technology Stack

**Backend:** Rust, Tokio, Alloy, Axum, SQLx, SQLite, Serde, tracing, Prometheus metrics
**Security fixtures:** Solidity, Foundry
**Dashboard:** React, TypeScript, Vite, Tailwind (optional), SSE
**Ops:** Docker, Docker Compose, GitHub Actions, Prometheus, Grafana

---

## Phase 0 — Project Discipline & The Thin Slice

**Goal:** Move one fake EIP-7702 event from input → SQLite → REST → SSE → live dashboard, before real blockchain logic.

- 0.1 Create repo structure; add `README.md` (with Definition of Done) and `V2_BACKLOG.md`.
- 0.2 Write the project contract (V1 DoD at top of README; out-of-scope list in backlog).
- 0.3 Build the thin slice:
  1. Rust process creates one hardcoded delegation event
  2. Save to SQLite
  3. `GET /api/v1/delegations`
  4. `GET /api/v1/events` (SSE)
  5. React dashboard displays it
  6. Dashboard updates live without refresh

**Exit criteria**

- Repo discipline files exist
- SQLite migration works
- Axum health/ready + delegation APIs work
- POST persists before broadcast
- SSE updates dashboard live
- React initial/loading/empty/error states work
- Backend checks/tests pass; frontend production build passes
- README has exact run + demo steps

---

## Phase 1 — Rust Foundation & Domain Model

**Goal:** Clean backend skeleton in a single crate.

- 1.1 Backend modules: `main.rs, config.rs, domain.rs, error.rs, source.rs, chain.rs, tracker.rs, analyzer.rs, policy.rs, storage.rs, api.rs, telemetry.rs`
- 1.2 Core domain types: `BlockRef`, `Authorization`, `DelegationChange`, `ChainUpdate` (use Alloy types)
- 1.3 Config from env: `DATABASE_URL, RPC_HTTP_URL, RPC_WS_URL, CHAIN_ID, API_BIND_ADDRESS, RUST_LOG, CONFIRMATION_DEPTH`; provide `.env.example`; redacted config display
- 1.4 Typed errors (RPC, unsupported tx, invalid authorization, DB, reorg, analysis, missing code)
- 1.5 Structured logging with `tracing`

**Exit criteria**

- `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test` pass
- No secrets in logs
- Health/ready endpoints; clean startup failures

---

## Phase 2 — EIP-7702 Mechanics & Foundry Fixtures

**Goal:** Understand & demonstrate EIP-7702 before building the analyzer.

- 2.1 Safe delegation fixture (owner, authenticated execution, nonce, deadline, chain+account-bound signatures)
- 2.2 Vulnerable fixtures:
  - A: unsafe initializer (public, no guard)
  - B: public arbitrary `execute` (no auth)
  - C: replayable signed execution (missing account/chainId/nonce/deadline)
- 2.3 Foundry exploit + safe-counterpart tests
- 2.4 `docs/eip-7702-mechanics.md` (authorization list/tuple, delegation indicator, execution/storage context, nonce, clearing delegation, vs proxy)

**Exit criteria**

- All Foundry tests pass; each unsafe fixture has a working exploit; each safe fixture rejects it

---

## Phase 3 — Transaction Decoder & Fixture Replay

**Goal:** Decode EIP-7702 transactions from recorded JSON fixtures (deterministic before live RPC).

- 3.1 Collect fixtures (valid, multiple auths, chain-specific/agnostic, invalid sig, invalid nonce, set delegation, clear delegation, duplicate authority, non-7702 tx) under `fixtures/transactions/`
- 3.2 Decode: tx type, authorization list, chain id, implementation, nonce, signature, recovered authority
- 3.3 Validate semantics separately from decoding
- 3.4 CLI: `inspect-file`, `inspect-tx-json`

**Exit criteria**

- Every fixture has an expected result; typed errors; signature recovery tested; clearing handled; multiple auths in order; deterministic JSON output

---

## Phase 4 — Canonical Delegation Tracker & Reorg Engine

**Goal:** Correct account→implementation state over time, including reorgs. (Protocol-engineering centerpiece.)

- 4.1 Schema: `blocks, transactions, authorizations, delegation_changes, current_delegations, reorg_events` (+ canonical, applied_at, reverted_at)
- 4.2 Apply block (verify parent, store, decode, record previous delegation, apply new, emit events)
- 4.3 Revert block (reverse changes, restore previous, mark noncanonical, revert alerts, emit reorg)
- 4.4 Reorg simulation tests (A→B→C replaced by D→E)
- 4.5 Idempotency (re-apply/re-revert safe)

**Exit criteria**

- Correct current delegation after reorgs; history preserves canonical/noncanonical; idempotent; alerts follow canonical state; DB transactions prevent partial application

---

## Phase 5 — Evidence-Based Security Analyzer

**Goal:** Analyze implementations without overclaiming. Verified source / fixtures first; bytecode-only = lower confidence.

- 5.1 Implementation resolver (fetch bytecode, hash, cache, first/last seen, verified source/ABI when available)
  - Cache key: `chain_id + implementation_address + bytecode_hash + analyzer_version`
- 5.2 Rule format: `rule_id, title, severity, confidence, evidence, explanation, remediation`
  - Severity: Informational/Low/Medium/High/Critical
  - Confidence: Heuristic/Probable/Confirmed
- 5.3 V1 rules only:
  - DL-001 Unsafe initialization
  - DL-002 Unprotected arbitrary execution
  - DL-003 Missing signed-action replay controls
- 5.4 Positive + negative fixtures per rule (measure TP/FP/FN)
- 5.5 Version findings (analyzer_version, rule_version, source_hash, bytecode_hash, timestamp)

**Exit criteria**

- 3 rules; safe+vulnerable fixtures; evidence + remediation; severity ≠ confidence; cached; no universal-detection claims

---

## Phase 6 — Risk Policy & Account-Level Intelligence

**Goal:** Convert findings into explainable account risk.

- 6.1 `config/risk-policy.yaml` (rule weights + thresholds; document that weights are policy)
- 6.2 Account risk result (impl, bytecode hash, delegation block, canonical status, findings, score, level, confidence, last analyzed)
- 6.3 Anomaly signals (new impl, delegation spikes, rapid redelegation, shared impl, missing source) — labeled heuristic
- 6.4 Alert lifecycle: `ACTIVE, RESOLVED, REVERTED_BY_REORG, SUPERSEDED`

**Exit criteria**

- Scores traceable to rules; anomalies separate from vulns; alerts follow canonical state; reorgs revert/restore alerts; policy change triggers re-eval

---

## Phase 7 — Live RPC Ingestion

**Goal:** Move from fixtures to live network data (after decoder + reorg tests pass).

- 7.1 HTTP backfill (range, checkpoint, resume)
- 7.2 Live block ingestion (WS new-heads; verify parent; reconcile ancestor; revert/apply)
- 7.3 Recovery/restart from last canonical block
- 7.4 Provider resilience (retry/backoff, timeout, rate limits, health, optional secondary RPC)
- 7.5 Network scope: Sepolia first, then optional narrow mainnet range

**Exit criteria**

- Continuous processing; restart resumes; parent mismatch reconciles; RPC failure doesn’t corrupt state; dashboard gets live events; reorg simulation still passes

---

## Phase 8 — Product API

**Goal:** Stable interface for dashboard + external users.

Endpoints:

```text
GET /api/v1/accounts/{address}/delegation
GET /api/v1/accounts/{address}/history
GET /api/v1/implementations/{address}
GET /api/v1/implementations/{address}/findings
GET /api/v1/transactions/{hash}
GET /api/v1/delegations
GET /api/v1/alerts
GET /api/v1/stats
GET /api/v1/events
GET /health
GET /ready
GET /metrics
```

- 8.1 Pagination (limit, cursor, sort, filters)
- 8.2 Validation (addresses, tx hashes, limits, chain ids, filters)
- 8.3 OpenAPI spec + samples
- 8.4 Basic rate limiting on expensive endpoints

**Exit criteria**

- API tests pass; structured errors; pagination; OpenAPI; SSE reconnect handled; no leaks

---

## Phase 9 — Live Dashboard

**Goal:** Clear demo of delegation activity + security risk (not a generic explorer).

Pages:

- Overview (active delegations, 24h, analyzed impls, high-risk, reorgs, ingestion health)
- Live delegation feed (SSE-updated table)
- Account details (current delegate, history, nonce, tx/block, findings, reorged history marked, cleared events)
- Implementation details (address, bytecode hash, first/last seen, delegated accounts, source status, findings, evidence, remediation)
- Reorg timeline (commit → apply → revert → remove → replacement)
- System health (RPC, last block, lag, queue, failures)

**Exit criteria**

- SSE feed works; findings include evidence; canonical vs reverted visibly distinct; mobile usable; empty/loading/error states; no heuristic shown as proven exploit

---

## Phase 10 — Observability & Operational Hardening

**Goal:** Operable and debuggable.

- 10.1 Metrics (`blocks_processed_total, transactions_processed_total, authorizations_detected_total, active_delegations, implementations_analyzed_total, findings_total, reorgs_total, rpc_errors_total, block_processing_duration_seconds, analysis_duration_seconds, ingestion_lag_blocks, sse_clients`)
- 10.2 Prometheus + Grafana via Docker Compose
- 10.3 Graceful shutdown (stop new work, finish/cancel current block, flush DB, close SSE, save checkpoint)
- 10.4 Failure behavior (one analysis failure ≠ ingestion stop; statuses PENDING/RUNNING/COMPLETED/FAILED/SKIPPED)

**Exit criteria**

- `docker compose up` starts everything; metrics in Prometheus; Grafana loads; restart preserves state; analysis failure doesn’t stop ingestion; graceful shutdown

---

## Phase 11 — Testing, Benchmarking & Security Hardening

**Goal:** Prove correctness; document limits.

- 11.1 Test pyramid: unit (decoder, sig recovery, state changes, rules, scoring); integration (SQLite, API, SSE, fixture replay, analysis); stateful (random commit/revert/reorg, repeated/duplicate, multi-auth, clear, restore); Foundry (vuln/safe/exploit)
- 11.2 Property tests (apply+revert restores state; double-apply no dup; noncanonical finding not active; current delegation = latest canonical)
- 11.3 Perf benchmark (blocks/s, auths/s, analysis duration, API latency, reorg rollback, memory) — no unmeasured claims
- 11.4 `docs/threat-model.md` (malicious RPC, reorgs, malformed tx, DB corruption, untrusted source, false positives, resource exhaustion, API abuse, secret leakage)

**Exit criteria**

- CI green; reorg properties tested; FP cases documented; reproducible benchmark; threat model + limitations public

---

## Phase 12 — Polish, Launch & Resume Packaging

**Goal:** Turn engineering into an interview asset.

- 12.1 README (problem, why 7702 security, architecture diagram, demo GIF/video, quick start, example finding, reorg demo, rules, stack, results, threat model, limitations, roadmap)
- 12.2 Docs: `architecture.md, eip-7702-mechanics.md, detection-rules.md, reorg-model.md, threat-model.md`
- 12.3 Demo video (90–120s): start stack → safe delegation → dangerous delegation + evidence → reorg → dashboard reverts → API response
- 12.4 Engineering article (e.g., "Building a Reorg-Aware EIP-7702 Security Intelligence Platform in Rust")
- 12.5 Resume bullets (only after implementation; add numbers only after measuring)

**Deliverable:** Public, documented, reproducible, demo-ready repository.

---

## Phase Completion Order

```text
Phase 0  — Thin slice
Phase 1  — Rust foundation
Phase 2  — EIP-7702 Foundry fixtures
Phase 3  — Decoder
Phase 4  — Canonical tracker and reorgs
Phase 5  — Three analyzer rules
Phase 6  — Risk policy
Phase 7  — Live RPC ingestion
Phase 8  — API
Phase 9  — Live dashboard
Phase 10 — Observability
Phase 11 — Testing and benchmarks
Phase 12 — Launch and resume packaging
```

## Accuracy Rules (apply throughout)

- Don't label every `delegatecall`/upgradeable impl as a vulnerability
- Separate heuristics from confirmed findings; severity ≠ confidence
- Prove rules with vulnerable + safe fixtures
- Track bytecode hashes, not only addresses
- Handle chain id + authorization nonce correctly
- Treat reorg rollback as correctness, not optional
- Document what the analyzer cannot prove
- Never claim "detects all EIP-7702 vulnerabilities"
