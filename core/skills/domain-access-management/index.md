# Domain Access Management

## Stack overview

Authentication, authorization, BOLA/IDOR, session controls, and architectural auth risks grouped by function.

## Top threats

- **Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists.**: 19 metrics (`PY-100`, `PY-105`, `PY-011`, `PY-013`)
- **Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering.**: 14 metrics (`NJS-009`, `NJS-016`, `NJS-024`, `NJS-026`)
- **Cache key по subject+scope+tenant+ttl.**: 1 metrics (`APP-119`)
- **Central revocation + backchannel logout.**: 1 metrics (`APP-108`)
- **Fail-closed при ошибке внешнего IdP.**: 1 metrics (`APP-102`)
- **Rate-limit + progressive delay + lockout.**: 1 metrics (`APP-112`)
- **Re-auth/step-up перед привилегированными операциями.**: 1 metrics (`APP-105`)
- **Risk-based controls, captcha/behavioral checks.**: 1 metrics (`APP-117`)
- **Scope-bound short-lived tokens per service.**: 1 metrics (`APP-107`)
- **Signed delegation token + bounded TTL + audit.**: 1 metrics (`APP-115`)
- **Вводить idempotency-key и single-flight для token issue.**: 1 metrics (`APP-100`)
- **Включать tenant claim + enforce в policy layer.**: 1 metrics (`APP-113`)
- **Для create/update использовать явный whitelist полей (DTO/pick), блокировать системные/привилегированные атрибуты и валидировать типы.**: 1 metrics (`CWE-20-ORM-MASS-ASSIGN`)
- **Для чувствительных операций использовать `ipcMain.handle` + строгую валидацию payload и проверку источника/role.**: 1 metrics (`DSK-105`)
- **Исключить вывод токенов даже в debug-режиме, применять редактирование/маскирование чувствительных данных в логах.**: 1 metrics (`MOB-010`)
- **Использовать POST/PUT/PATCH + CSRF guards.**: 1 metrics (`APP-109`)
- **Обязательный MFA gate для high-risk операций.**: 1 metrics (`APP-104`)
- **Обязательный timeout + retry budget + circuit breaker.**: 1 metrics (`APP-101`)
- **Привязка токена к nonce/device/session fingerprint.**: 1 metrics (`APP-103`)
- **Проверять subject/scope до исполнения job.**: 1 metrics (`APP-110`)
- **Ротация по SLA + автоотзыв компрометированных ключей.**: 1 metrics (`APP-111`)
- **Централизованный security audit log.**: 1 metrics (`APP-114`)
- **Явная обработка ошибок + forced re-auth.**: 1 metrics (`APP-116`)
- **Явный consent prompt + least-scope default.**: 1 metrics (`APP-118`)
- **Явный least-privilege allowlist ролей.**: 1 metrics (`APP-106`)

## Pattern catalog

Complete Anti-Pattern / Safe-Pattern definitions live in [`patterns.md`](patterns.md). The table below is a **table of contents** by metric ID.

| ID | Metric | Stack |
|---|---|---|
| `PY-100` | Fail-Open Auth (env token) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PY-105` | BOLA in Django queryset | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `NJS-009` | JWT verify without strict policy | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-016` | Missing ownership check (IDOR/BOLA) | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-024` | Weak session cookie policy | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-026` | Mass Assignment | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `PY-011` | JWT algorithm confusion | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PY-013` | ORM mass assignment | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FTS-018` | Hidden UI Auth Bypass | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `FTS-019` | Loose comparison in access checks | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `APP-100` | Duplicate token issuance in parallel flow | Вводить idempotency-key и single-flight для token issue. |
| `APP-101` | Missing client timeout policy | Обязательный timeout + retry budget + circuit breaker. |
| `APP-102` | Fail-open fallback on auth provider error | Fail-closed при ошибке внешнего IdP. |
| `APP-103` | Missing token replay binding | Привязка токена к nonce/device/session fingerprint. |
| `APP-104` | Missing MFA enforcement on critical action | Обязательный MFA gate для high-risk операций. |
| `APP-105` | Admin action without re-auth | Re-auth/step-up перед привилегированными операциями. |
| `APP-106` | Broad role wildcard in policy | Явный least-privilege allowlist ролей. |
| `APP-107` | Static service token reuse | Scope-bound short-lived tokens per service. |
| `APP-108` | Missing session revocation propagation | Central revocation + backchannel logout. |
| `APP-109` | Privileged action via GET | Использовать POST/PUT/PATCH + CSRF guards. |
| `APP-110` | Missing authz check in background worker | Проверять subject/scope до исполнения job. |
| `APP-111` | Weak API key rotation policy | Ротация по SLA + автоотзыв компрометированных ключей. |
| `APP-112` | No lockout on auth brute force | Rate-limit + progressive delay + lockout. |
| `APP-113` | No tenant isolation in access token | Включать tenant claim + enforce в policy layer. |
| `APP-114` | Missing auth audit trail | Централизованный security audit log. |
| `APP-115` | Insecure impersonation flow | Signed delegation token + bounded TTL + audit. |
| `APP-116` | Silent token refresh failures | Явная обработка ошибок + forced re-auth. |
| `APP-117` | No anti-automation controls on auth APIs | Risk-based controls, captcha/behavioral checks. |
| `APP-118` | Missing consent boundary for delegated scopes | Явный consent prompt + least-scope default. |
| `APP-119` | Auth cache poisoning risk | Cache key по subject+scope+tenant+ttl. |
| `PY-010` | Insecure random for security tokens | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PY-012` | SQL string interpolation in execute | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PY-017` | Missing rate limit on sensitive endpoints | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PY-023` | Playwright context isolation missing per session | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PY-026` | Sensitive data in logs | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PY-028` | Missing CSRF on state-changing form endpoints | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `DJA-007` | Insecure Cookie Flags (SESSION/CSRF) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `DJA-012` | Unsafe Session Serializer: `PickleSerializer` | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `DJA-014` | Weak password hasher | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `MOB-010` | Hardcoded Tokens in Debug Logs | Исключить вывод токенов даже в debug-режиме, применять редактирование/маскирование чувствительных данных в логах. |
| `DSK-105` | Insecure IPC channel for sensitive actions | Для чувствительных операций использовать `ipcMain.handle` + строгую валидацию payload и проверку источника/role. |
| `NJS-032` | Insecure JWT Secret Storage via direct env read | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-033` | Weak mTLS/TLS config with `rejectUnauthorized: false` | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `FTS-002` | Insecure Client Storage: sensitive tokens/data in web storage | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `FTS-003` | Sensitive Console Logging in production builds | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `FTS-005` | Client-Side Logic Bypass: critical checks only in frontend | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `FTS-014` | Insecure Pseudo-Random for security tokens | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-755-PY` | Fail-Open Error Handling in auth-critical Python paths | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-384-PY` | Session Fixation in custom Python auth views | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-613-PY` | Insufficient Session Expiration in Python auth flows | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-770-PY` | Missing API Rate Limiting for auth/critical endpoints (Python) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-770-JS` | Missing API Rate Limiting in Node auth routes | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-20-ORM-MASS-ASSIGN` | ORM Mass Assignment via full payload object without explicit whitelist | Для create/update использовать явный whitelist полей (DTO/pick), блокировать системные/привилегированные атрибуты и валидировать типы. |
| `CWE-287-KEYCLOAK-JWT-AUD-ISS` | Missing `aud`/`iss` validation in Keycloak JWT verification (`python-jose`) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-613-KEYCLOAK-SESSION-CHECKS` | Weak session/token lifetime checks in Keycloak integration | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-862-NEXTJS-SERVER-ACTION` | Missing authorization checks in Next.js Server Actions (`'use server'`) | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |

## Verification

**Verification:** Check the gold testbed file(s) below for `Vulnerable: <ID>` markers (static Semgrep + `detection-matrix.md` ground truth).

- [`gold-standard-testbed/gap_fill_vulnerable.py`](../gold-standard-testbed/gap_fill_vulnerable.py)

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

