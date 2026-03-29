# Domain Data Privacy

## Stack overview

PII and secret leakage controls across logs, traces, browser storage, and runtime diagnostics.

## Top threats

- **Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering.**: 19 metrics (`FTS-002`, `FTS-003`, `FTS-008`, `NJS-010`)
- **Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists.**: 17 metrics (`PY-002`, `PY-009`, `PY-026`, `DJA-008`)
- **Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input.**: 3 metrics (`CWE-798-CSH-CONFIG-SECRETS`, `CWE-384-CSH-STATIC-TOKEN-CONTEXT`, `CWE-532-CSH-OFFICE-PII-LOG`)
- **Sanitization pipeline до отправки в telemetry backend.**: 1 metrics (`LOG-012`)
- **Включить `window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)` для защиты экрана от скриншотов и записи.**: 1 metrics (`MOB-021`)
- **Маскирование ПДн и policy-based log redaction.**: 1 metrics (`RRC-001`)
- **Не передавать секреты в query string; использовать Authorization header/body и redaction policy для логов/телеметрии.**: 1 metrics (`CWE-359-AXIOS-PARAMS-LEAK`)
- **Перед логированием принудительно заменять/экранировать `\r` и `\n` (например, `\\r`/`\\n`), применять centralized log sanitizer.**: 1 metrics (`CWE-117-UNIVERSAL-CRLF`)
- **Передавать секреты через Secret Manager/ESO/Vault, исключать plaintext ENV в Docker/K8s manifests.**: 1 metrics (`CWE-312-ENV`)
- **Хранить ключи только во внешнем secret manager/env, маскировать в логах и исключать из репозитория/trace output.**: 1 metrics (`CWE-200-OPENROUTER-APIKEY-LEAK`)

## Pattern catalog

Complete Anti-Pattern / Safe-Pattern definitions live in [`patterns.md`](patterns.md). The table below is a **table of contents** by metric ID.

| ID | Metric | Stack |
|---|---|---|
| `FTS-002` | Sensitive data in client storage | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `FTS-003` | Sensitive console logging | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `FTS-008` | Source-map data exposure | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `PY-002` | Error detail leakage | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PY-009` | Hardcoded secret in code | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PY-026` | Secrets in logs | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `NJS-010` | Stacktrace leakage in API | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-035` | Sensitive data retained in memory | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `RRC-001` | PII leakage in logs (Enterprise Compliance) | Маскирование ПДн и policy-based log redaction. |
| `LOG-012` | PII/secret leakage in observability | Sanitization pipeline до отправки в telemetry backend. |
| `DJA-008` | Hardcoded Secret Key | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `DJA-010` | Verbose error leakage to client | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `DJA-015` | Unsafe logout redirect | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `DJA-018` | Missing `LoginRequiredMixin` on CBV | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `MOB-021` | UI Privacy Missing FLAG_SECURE | Включить `window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)` для защиты экрана от скриншотов и записи. |
| `NJS-005` | Missing process crash guards for async/runtime failures | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-019` | Abuse of process.env directly in business logic | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-034` | Unsafe stream piping without error handlers | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `FTS-017` | Unsafe Message Parsing in message handlers | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `FTS-020` | Unhandled Async Errors in Promise/async flows | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-327-PY` | Weak Hash Algorithms in Python (MD5/SHA1) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-328-PY` | Weak Crypto Mode (ECB) in Python | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-338-PY` | Predictable Random for tokens/passwords in Python | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-327-JS` | Weak Hash/Cipher in Node.js crypto | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-338-JS` | Predictable Random for session IDs in JavaScript | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-200-PY` | Information Disclosure via hardcoded internal/Sheets URLs | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-200-JS` | Source leak via sensitive fields in model toString | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-117-PY` | Log Injection in Python logging with unsanitized user input | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-117-JS` | Log Injection in JS/Node logs | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-404-JS` | Resource Leak with stream handles in Node.js | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-312-JS` | Cleartext token storage in browser localStorage | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-312-PY` | Cleartext secret/password in Python settings | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-532-PY` | Sensitive data written to logs in plaintext | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-312-ENV` | Cleartext secrets in environment/Docker configuration | Передавать секреты через Secret Manager/ESO/Vault, исключать plaintext ENV в Docker/K8s manifests. |
| `CWE-532-PY-DECORATOR` | PII leak in Python decorator-based logging | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-117-UNIVERSAL-CRLF` | Log Injection via unsanitized CRLF in user-controlled log fields | Перед логированием принудительно заменять/экранировать `\r` и `\n` (например, `\\r`/`\\n`), применять centralized log sanitizer. |
| `CWE-74-PY-LDAP` | LDAP Injection in Python (`ldap3`) filter construction | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-74-JS-LDAP` | LDAP Injection in Node.js (`ldapjs`) filter concatenation | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-359-AXIOS-PARAMS-LEAK` | Sensitive data exposure via Axios `params` query string (`token/password/secret`) | Не передавать секреты в query string; использовать Authorization header/body и redaction policy для логов/телеметрии. |
| `CWE-524-AXIOS-CACHE-AUTH` | Missing `Cache-Control: no-store` on Axios GET to `/api/user/*` or `/api/auth/*` | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-200-NEXTJS-CLIENT-ENV` | Secret env leak: server-side env vars used in `use client` components | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-200-OPENROUTER-APIKEY-LEAK` | Hardcoded LLM provider API keys in code/logs | Хранить ключи только во внешнем secret manager/env, маскировать в логах и исключать из репозитория/trace output. |
| `CWE-922-FASTAPI-HEADER-LOG` | Sensitive headers (`Authorization`, `Set-Cookie`) logged by request middleware | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-798-CSH-CONFIG-SECRETS` | Hardcoded API keys/passwords in `.config`, `Settings.settings`, `.resx` for C# desktop ... | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CWE-384-CSH-STATIC-TOKEN-CONTEXT` | Session fixation risk via `public static` token/user context fields in VSTO classes | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CWE-532-CSH-OFFICE-PII-LOG` | PII leakage: logging Office object properties (`MailItem.SenderEmailAddress`, `Document... | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |

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

