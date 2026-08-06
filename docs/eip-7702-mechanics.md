# EIP-7702 Mechanics

## What it is

EIP-7702 introduces a "set code" transaction (a new EIP-2718 type) carrying an
`authorization_list`. Each entry is a tuple `[chain_id, address, nonce, y_parity, r, s]`.
For each valid tuple, the signing EOA ("authority") gets a **delegation designator**
as its code: `0xef0100 ‖ address`.

## The authorization tuple

- `chain_id` — must equal the current chain ID, or `0` for "any chain" (universal).
- `address` — the implementation to delegate to. `address(0)` **clears** the delegation
  (resets the account to the empty-code hash).
- `nonce` — must equal the authority account's current nonce when applied.
- `y_parity, r, s` — signature over `keccak(MAGIC ‖ rlp([chain_id, address, nonce]))`.

Tuples are processed at the start of the transaction, after the sender's nonce is
incremented; a valid tuple sets the authority's code and bumps the authority's nonce.

## Execution & storage context

Delegated code executes **in the authority EOA's context**: `address(this)` is the EOA,
storage reads/writes hit the EOA's storage, and its balance is the EOA's balance —
effectively a permanent `delegatecall` into the implementation.
Do **not** rely on `tx.origin == msg.sender`; a delegated EOA can make nested calls.

## Clearing a delegation

Submit an authorization with `address = address(0)`. This is the protocol-sanctioned
way to return the account to an EOA-like state.

## Why delegate contracts must be defensive

Because anyone can call a delegated EOA and the code runs as that account, the
implementation must authenticate every privileged action. The EIP explicitly warns to
sign over at least: replay protection (nonce), value, gas, target, and calldata, and to
verify initialization via the EOA key (no initcode runs under 7702).

## The three failure classes (our fixtures)

- **DL-001 Unsafe initialization** — public/unguarded initializer → front-run or reset
  to attacker-controlled owner. Safe: gate to `msg.sender == address(this)`, one-time.
- **DL-002 Unprotected arbitrary execution** — public `execute` with no auth → anyone
  drains the account. Safe: require an EOA signature over the exact call.
- **DL-003 Missing replay controls** — signed action omits nonce/deadline/chainId/account
  → one signature replayed forever / cross-chain. Safe: bind all four into the digest and
  consume the nonce before the external call.

## vs. Proxies

A proxy is a contract that `delegatecall`s an implementation. EIP-7702 makes an _EOA_
behave like that proxy, but there is no constructor/initcode step, and the "proxy" is a
key-controlled account — which is exactly why key-bound signature checks matter.
