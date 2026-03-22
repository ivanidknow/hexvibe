# Advanced Agent & Cloud

## Stack overview

Covers automation agents that combine **headless browsers** (Playwright), **JavaScript/Node** surfaces (Next.js public env), **Python** workers and queues (RQ/redis), **object storage** (S3/MinIO-style), **reverse proxies** (Nginx), **egress controls**, and **real-time** browser APIs (WebRTC). Metrics are prefixed **`AAC`**.

**Product alignment:** critical for **Dion Agent** — browser-bound automation, queues, and cloud-adjacent controls must stay aligned with these metrics.

## Top threats

- **SSRF and navigation abuse** via browser automation (`AAC-001`, `AAC-008`).
- **Secret and PII leakage** through client bundles, traces, or logs (`AAC-002`, `AAC-003`, `AAC-009`).
- **Unsafe deserialization and queue trust** (`AAC-004`) and **weak object-store policy** (`AAC-005`).
- **Broken identity validation** against OIDC/Keycloak expectations (`AAC-006`).
- **Missing rate limits / DoS** at the edge (`AAC-007`) and **ambient capture** (`AAC-010`).

## Pattern catalog

Complete Anti-Pattern / Safe-Pattern definitions live in [`patterns.md`](patterns.md). The table below is a **table of contents** by metric ID.

| ID | Metric | Stack |
|---|---|---|
| `AAC-001` | SSRF in Playwright | `ALLOWED_HOSTS = {"cdn.example.com"}` `u = urlparse(userInput)` `if u.hostname not in ALLOWED_HOSTS: raise ValueError("url not allowed")` `await page.goto(userInput)` |
| `AAC-002` | Leakage in Playwright Traces | `await context.tracing.start(screenshots=False)` или маскирование PII перед экспортом трейса |
| `AAC-003` | Next.js Client-side Secret Leak | `const key = process.env.STRIPE_SECRET_KEY` (только серверные модули / Route Handlers без `NEXT_PUBLIC_`) |
| `AAC-004` | Insecure RQ (Redis Queue) Job | `json.loads(raw_job)` или `msgpack.loads` + явная схема данных |
| `AAC-005` | Insecure MinIO Pre-signed URL | `expires=timedelta(seconds=45)` + проверка владельца объекта и `method` GET-only где возможно |
| `AAC-006` | Keycloak SSO Bypass | `claims = jwt.decode(token, key, audience=..., issuer=..., options={"verify_exp": True})` |
| `AAC-007` | Nginx Rate Limit Missing | `limit_req zone=api burst=20 nodelay;` в том же `location` или выше по цепочке |
| `AAC-008` | Egress Proxy Bypass (Squid) | `HTTP_PROXY`/`HTTPS_PROXY` заданы на уровне контейнера; `Session(trust_env=True)` |
| `AAC-009` | Log Injection in Task Queues | `logger.info("job=%s", sanitize(redis_raw_payload))` |
| `AAC-010` | Insecure WebRTC/VAD Permissions | state-machine: явное `consentGiven === true` до вызова `getUserMedia` |
| `AAC-011` | MCP tool path/command handling without `abspath` and workspace boundary checks | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `AAC-012` | MCP tool arguments without Pydantic validation schema | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `AAC-013` | Non-atomic Redis read-modify-write in RQ workers without `WATCH`/Lua | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `AAC-014` | Missing `pydantic.BaseModel` validation for JSON responses from external AI APIs | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `AAC-015` | Logging full system prompts/context windows into observability sinks (CWE-1037) | Логировать только redacted metadata (hash/id/length), исключать system prompts и полный контекст из telemetry/logs by default. |
| `AAC-016` | Persisting raw model memory snapshots with secrets in traces (CWE-1037) | Перед трассировкой удалять секреты/PII из agent memory и применять denylist sensitive keys (`token`, `secret`, `api_key`). |
| `AAC-017` | Exporting chain-of-thought/internal reasoning to logs (CWE-1037) | Не логировать скрытые reasoning fields; сохранять только конечный ответ и технические метрики выполнения. |
| `AAC-018` | Storing unencrypted prompt history in persistent debug artifacts (CWE-1037) | Шифровать артефакты или отключать persistent prompt dumps в production; включать retention + secure erase policy. |
| `AAC-019` | MCP tool registry allows wildcard command execution (CWE-693) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `AAC-020` | Missing tenant isolation in shared vector store namespaces | Использовать server-side tenant mapping и immutable namespace binding, запретить namespace from external input. |
| `AAC-021` | Prompt template loaded from user-controlled path | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `AAC-022` | Unbounded retry loops on AI API errors | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `AAC-023` | External tool result injected into system role without sanitization | Нормализовать/санитизировать tool output и разделять роли (`system` immutable, external data only as user/tool role). |
| `AAC-024` | Agent callbacks execute network requests without egress allowlist | Вводить egress allowlist + DNS/IP validation и блокировать link-local/metadata ranges перед запросом. |
| `AAC-025` | Cache key for AI results misses auth/tenant dimension | Включать tenant/user scope и policy version в cache key, чтобы исключить cross-tenant data leakage. |
| `AAC-026` | Deserializing tool payload via `eval`/unsafe parser in agent runtime | Использовать безопасный JSON parser + strict schema validation и reject unknown fields до обработки. |
| `AAC-027` | LLM indirect injection: Base64 decode обработки ответа модели до валидации схемы (CWE-1... | Pydantic `model_validate` на сыром тексте ответа; для base64 — только после явного поля в схеме и max length; в TS — Zod + отказ от `Buffer.from(llm, "base64")` без policy. |
| `AAC-028` | LLM indirect injection: Hex / binary decode текста ассистента (CWE-1109) | Как AAC-027: строгая схема ответа, без `fromhex`/`hex` decode на необработанной строке модели. |
| `AAC-029` | Обфусцированная shell-команда в ответе LLM: `chr`/`ord` цепочка (CWE-1027) | Pydantic-схема ответа без `exec`/`system`; sandbox tool API. |
| `AAC-030` | Обфусцированная команда: `base64` + `eval` в JS от ассистента (CWE-1334) | Zod + deny `eval`/`Function` на данных модели. |
| `AAC-031` | PowerShell `-EncodedCommand` из текста модели (CWE-78) | Allowlist argv; no shell metacharacters from model. |
| `AAC-032` | Bash обёртка `$(echo ... \ | Парсер JSON + фиксированные команды. |
| `AAC-033` | `compile()` / `exec()` на обфусцированном Python из модели (CWE-94) | RestrictedPython или no code execution path. |
| `AAC-034` | Unicode homoglyph obfuscation в «команде» ассистента (CWE-1335) | Unicode NFKC + command allowlist. |
| `AAC-035` | Разделённая на части команда (`list` concat) из LLM (CWE-1027) | Фиксированный `argv` template; модель только заполняет allowlisted args. |
| `AAC-036` | Hex-строка как «данные», исполняемые через `bytes.decode` + `exec` (CWE-1337) | Schema deny raw hex blobs. |
| `AAC-037` | Obfuscated URL scheme в ответе (`data:`/`javascript:`) для tool callback (CWE-1338) | Strict URL parser + block dangerous schemes. |
| `AAC-038` | Многослойное кодирование: `b64decode` → `zlib` → `exec` (CWE-1340) | Single JSON schema; no chained decoders on model text. |
| `AAC-039` | Python: `codecs.decode` hex из поля ответа LLM до схемы (CWE-1027) | Pydantic `model_validate` на тексте; deny `codecs.decode` на LLM fields. |
| `AAC-040` | JS: `Buffer.from` base64 из текста ассистента → `eval` (CWE-1027) | Zod schema; block `eval`/`new Function` on model-derived buffers. |
| `AAC-041` | Python: `binascii.a2b_hex` на строке модели → `pickle.loads` (CWE-1109) | JSON-only; no binary deserialization from assistant output. |
| `AAC-042` | JS: `Uint8Array.from(atob(llmB64), ...)` без валидации схемы (CWE-1109) | Reject raw atob blobs unless schema allows with max length. |
| `AAC-043` | JWT из интеграции: `exp` > 24h на machine tokens (CWE-613) | Короткий TTL + rotation; явные `leeway`/`max_age` в verifier. |
| `AAC-044` | SSRF guard: прямой `httpx` к Azure IMDS из agent-кода (CWE-918) | Central HTTP wrapper; no IMDS literals in agent runtime. |

## Verification

**Verification:** Check the gold testbed file(s) below for `Vulnerable: <ID>` markers (static Semgrep + `detection-matrix.md` ground truth).

- [`gold-standard-testbed/aac_vulnerable.py`](../gold-standard-testbed/aac_vulnerable.py)
- [`gold-standard-testbed/aac_vulnerable.ts`](../gold-standard-testbed/aac_vulnerable.ts)

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

