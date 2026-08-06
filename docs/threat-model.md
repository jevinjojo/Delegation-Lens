# DelegationLens — Threat Model & Limitations

## Assets

- Correctness of canonical delegation state and history.
- Integrity of security findings and risk scores.
- Availability of ingestion, API, and dashboard.
- Confidentiality of RPC credentials.

## Threats & mitigations

| Threat                                                | Mitigation                                                                                                                                 |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| **Malicious / faulty RPC** returns bad blocks         | Parent-hash continuity checks; reorg reconciliation; typed `Rpc` errors; retry with backoff; failures are logged and skipped, never fatal. |
| **Reorgs** silently corrupt state                     | First-class revert/apply with per-change `previous_implementation`; DB transactions; stateful property test asserts invariants.            |
| **Malformed / non-7702 transactions**                 | Structural decode rejects non-7702 with a typed error; unrecoverable signatures flagged, never trusted.                                    |
| **DB corruption / partial writes**                    | Every block mutation is a single SQLite transaction (all-or-nothing); resume from last canonical block on restart.                         |
| **Untrusted / unverified source**                     | Bytecode-only analysis is capped at `Heuristic` confidence; findings never claim proof without source.                                     |
| **False positives / negatives**                       | Rules validated against safe + vulnerable fixtures; confidence is explicit; anomalies kept separate from vulnerabilities.                  |
| **Resource exhaustion** (huge responses, deep reorgs) | Cursor pagination with clamped limits; reorg depth capped (refuses > 128); bounded broadcast buffer.                                       |
| **API abuse**                                         | Fixed-window rate limiting on expensive endpoints; input validation returns 400, never 500.                                                |
| **Secret leakage**                                    | RPC URLs redacted in `Config` Debug/logs; secrets loaded from env, never committed.                                                        |

## Analyzer limitations (documented false-positive / negative cases)

- **FN:** a guard implemented via an unrecognized custom modifier may look "unguarded" or vice-versa (string heuristics, not full parsing).
- **FN:** proxies/libraries with indirection may hide an unauthenticated path from the source heuristic.
- **FP:** an `execute`-like function that is safe for reasons outside its own body (e.g., deploy-time config) may still flag.
- **Bytecode-only:** selector presence proves a function exists, not that it is exploitable — always `Heuristic`.
- The analyzer **does not** claim to detect all EIP-7702 vulnerabilities, perform symbolic execution, or prove exploitability.

## Explicitly out of scope (V1)

reth ExEx integration, multi-chain operational indexing, mainnet historical backfill, universal decompilation/symbolic execution, ML detection, automated transaction blocking, RBAC/multi-tenant. See `V2_BACKLOG.md`.
