# Hft Cpp Security

## Stack overview

See [`patterns.md`](patterns.md) for Anti-Pattern / Safe-Pattern definitions for this domain.

## Top threats

- Map concrete rows from the pattern table to your architecture.

## Pattern catalog

Complete Anti-Pattern / Safe-Pattern definitions live in [`patterns.md`](patterns.md). The table below is a **table of contents** by metric ID.

| ID | Metric | Stack |
|---|---|---|
| `HFT-001` | Buffer overflow via strcpy in order parser | CWE-119 |
| `HFT-002` | Buffer overflow via sprintf in hot loop | CWE-120 |
| `HFT-003` | Use-after-free on order object reuse | CWE-416 |
| `HFT-004` | Double free on exception path | CWE-415 |
| `HFT-005` | Integer overflow in price*volume | CWE-190 |
| `HFT-006` | Signed/unsigned mismatch in bounds checks | CWE-190 |
| `HFT-007` | Out-of-bounds access in ring buffer | CWE-787 |
| `HFT-008` | Unchecked memcpy length from network packet | CWE-120 |
| `HFT-009` | Format string vulnerability in logging | CWE-134 |
| `HFT-010` | Heap allocation without failure handling in hot path | CWE-703 |
| `HFT-011` | Missing null checks after map lookup pointer use | CWE-476 |
| `HFT-012` | Race condition on shared order book state | CWE-362 |
| `HFT-013` | ABA issue in lock-free stack/queue | CWE-367 |
| `HFT-014` | Missing memory fence in producer-consumer queue | CWE-362 |
| `HFT-015` | Dangling reference capture in async callback | CWE-416 |
| `HFT-016` | Unsafe reinterpret_cast for protocol structs | CWE-704 |
| `HFT-017` | Fixed-size char arrays for symbol fields without truncation checks | CWE-120 |
| `HFT-018` | Insecure C string concatenation in risk rule builder | CWE-120 |
| `HFT-019` | Missing timeout on market data socket reads | CWE-400 |
| `HFT-020` | File descriptor leak in reconnect loop | CWE-772 |
| `HFT-021` | Unbounded retry loop on exchange gateway errors | CWE-400 |
| `HFT-022` | Unsafe deserialization of binary snapshots | CWE-502 |
| `HFT-023` | Missing authentication on admin command channel | CWE-306 |
| `HFT-024` | Hardcoded credentials in market adapter | CWE-798 |
| `HFT-025` | Integer truncation converting notional to int32 | CWE-197 |
| `HFT-026` | Overflow in timestamp arithmetic | CWE-190 |
| `HFT-027` | Missing input validation on protocol enum values | CWE-20 |
| `HFT-028` | Uninitialized memory used in message serialization | CWE-457 |
| `HFT-029` | Shared memory segment permissions too broad | CWE-732 |
| `HFT-030` | Insecure random for session/order IDs | CWE-330 |
| `HFT-031` | Missing bounds checks in FIX tag parser | CWE-130 |
| `HFT-032` | Unsafe temporary file usage for snapshots | CWE-377 |
| `HFT-033` | Exposure of sensitive config via debug dumps | CWE-532 |
| `HFT-034` | Missing crypto-agility in transport ciphers config | CWE-327 |
| `HFT-035` | Zeroization missing for in-memory private keys | CWE-1037 |

## Verification

**Verification:** Check the gold testbed file(s) below for `Vulnerable: <ID>` markers (static Semgrep + `detection-matrix.md` ground truth).

- [`gold-standard-testbed/`](../gold-standard-testbed/) (see `detection-matrix.md` for ID → file mapping)

After changing [`patterns.md`](patterns.md), run from the repo root:

```bash
python scripts/sync_semgrep.py
```

## Workflow: Recon → Scan → Verify

### 1) Recon
- Map entrypoints, data flows, and trust boundaries for this stack.
- Identify which metrics in [`patterns.md`](patterns.md) apply to the code under review.

### 2) Scan
- Run Semgrep with `semgrep-rules/<skill>.yaml` (generated) and correlate with Anti-Patterns.
- Eliminate findings that cannot bind to a metric row.

### 3) Verify
- Confirm markers or scanner hits for touched IDs in the gold testbed when adding metrics.
- Emit findings as `Vulnerable: <PREFIX>-<NNN>` in written reviews.

