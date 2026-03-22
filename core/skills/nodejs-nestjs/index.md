# Node.js / NestJS

## Stack overview

**NestJS** / Express patterns: validation pipes, ORM raw queries, CORS, JWT, throttling, and logging. Metrics are prefixed **`NST`**.

## Top threats

- Prototype pollution and CORS (`NST-001`, `NST-002`).
- SQL/Prisma injection and SSRF (`NST-004`, `NST-005`, `NST-014`).
- AuthZ and guard mistakes (`NST-006`, `NST-008`, `NST-015`, `NST-016`).

## Pattern catalog

Complete Anti-Pattern / Safe-Pattern definitions live in [`patterns.md`](patterns.md). The table below is a **table of contents** by metric ID.

| ID | Metric | Stack |
|---|---|---|
| `NST-001` | Prototype Pollution в DTO merge | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-002` | Insecure CORS (`origin: *`) | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-003` | Missing global ValidationPipe | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-004` | TypeORM SQL Injection (query string concat) | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-005` | Prisma Raw Injection (`$queryRawUnsafe`) | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-006` | Open Redirect in controller | `CWE-601` |
| `NST-007` | Hardcoded secrets in source | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-008` | JWT verify without algorithm allowlist | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-009` | Missing body size limits | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-010` | Verbose exception leak | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-011` | Info leak in Swagger DTO | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-012` | Unsafe implicit type conversion | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-013` | Raw HTML in template rendering | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-014` | SSRF in `HttpService` | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-015` | Missing rate limiting in root module | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-016` | Insecure Reflector usage in Guard | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-017` | File upload without magic number check | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-018` | Insecure bcrypt rounds | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-019` | XXE risk in xml2js parsing | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-020` | Log Injection | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-021` | CSV Injection in Node/NestJS export handlers (CWE-1236) | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-022` | Debug message disclosure in production exception filter (CWE-1295) | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-023` | CSV export from untrusted DTO fields without normalization (CWE-1236) | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-024` | `localStorage` с access/refresh токенами (CWE-312) | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-025` | PII в `localStorage` как JSON (CWE-312) | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-026` | Refresh token в `sessionStorage` без ротации (CWE-532) | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |

## Verification

**Verification:** Check the gold testbed file(s) below for `Vulnerable: <ID>` markers (static Semgrep + `detection-matrix.md` ground truth).

- [`gold-standard-testbed/nestjs_vulnerable.ts`](../gold-standard-testbed/nestjs_vulnerable.ts)

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

