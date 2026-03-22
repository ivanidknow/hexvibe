# FastAPI / Async SQLAlchemy

## Stack overview

Async **FastAPI** APIs with **Encode Databases** / SQLAlchemy patterns, **SlowAPI**, **Pydantic**, and Python security baselines. Metrics are prefixed **`FAS`**.

## Top threats

- Injection and unsafe query construction (`FAS-004`, `FAS-005`, `FAS-021`, `FAS-024`–`FAS-027`).
- Broken async/resource hygiene (`FAS-006`–`FAS-009`, `FAS-020`).
- Information disclosure and misconfiguration (`FAS-010`–`FAS-013`, `FAS-019`).
- AuthZ and object-level flaws (`FAS-016`, `FAS-017`, `FAS-018`).

## Pattern catalog

Complete Anti-Pattern / Safe-Pattern definitions live in [`patterns.md`](patterns.md). The table below is a **table of contents** by metric ID.

| ID | Metric | Stack |
|---|---|---|
| `FAS-001` | SlowAPI: неверный порядок декораторов `limit` | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-002` | SlowAPI: endpoint без `request: Request` | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-003` | SlowAPI: нет `response` при необходимости модификации заголовков | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-004` | SQLi: интерполяция значений в SQL (без `:param`) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-005` | SQLi: конкатенация строк в SQL (без `:param`) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-006` | Transaction Leak: несколько `execute()` без `async with database.transaction()` | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-007` | Missing `await` на async DB call | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-008` | Global Client Reuse: создание `AsyncClient`/DB-коннекта внутри хендлера | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-009` | Missing Timeouts: асинхронные сетевые вызовы без `timeout` | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-010` | PII Leakage in Logs: логирование `Request`/секретных полей без маскирования | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-011` | Exposed Docs in Prod: Swagger/ReDoc включены в production | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-012` | Insecure CORS Policy: `allow_origins=["*"]` | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-013` | Pydantic Arbitrary Types: `arbitrary_types_allowed=True` в модели | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-014` | Background Task Exception Handling: задача без `try/except` | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-015` | Large Payload DoS: upload endpoint без лимита размера тела | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-016` | Host/Header Injection: отсутствие валидации `Host` и `X-` заголовков | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-017` | Mass Assignment Protection: прямой маппинг DTO в DB-модель | `OWASP API Security Top 10 (API3: Broken Object Property Level Authorization); FastAPI Production Readiness (strict input models)` |
| `FAS-018` | Insecure File Uploads: нет защиты от path traversal и magic-bytes проверки | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-019` | Verbose Error Messages: возврат raw Exception в HTTP-ответ | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-020` | Async Context Leakage: dependency без `yield/finally` не закрывает ресурсы | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-021` | OS Command Injection: shell-команда строится из пользовательского ввода | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-022` | Unsafe Deserialization: `pickle.loads`/`yaml.load` на недоверенных данных | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-023` | CSRF on Cookie Session: state-changing endpoint без CSRF-токена | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-024` | SSTI: пользовательский шаблон рендерится на сервере | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-025` | Code Injection: выполнение пользовательского кода через `eval/exec` | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-026` | Command Injection: небезопасный shell-вызов через `os.system`/`subprocess(..., shell=Tr... | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-027` | Unsafe Imports: динамический `__import__` из пользовательского ввода | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-028` | Excessive Data Exposure: `response_model` equals DB model without excluding sensitive f... | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-029` | Verbose error disclosure in custom `exception_handler` via `str(exc)` / `repr(exc)` | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-030` | Unsafe `FileResponse` path from user input discloses internal filesystem paths | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-031` | CSV Injection in export endpoints: user cells written without formula neutralization (C... | Атакующий присылает файл/строку с ячейкой вроде =SUM(1+1) cmd\ |
| `FAS-032` | Production logs expose full debug exception payloads (CWE-1295) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-033` | CSV export builds rows from raw query params without sanitization (CWE-1236) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-034` | FastAPI middleware prints request/response debug internals in production (CWE-1295) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `FAS-035` | Paladin: утечка `UserAuthData` (password_hash, internal_id) в JSON ответе (CWE-201) | Use Pydantic response models with explicit field exclusions; map domain entities to public DTOs only. |

## Verification

**Verification:** Check the gold testbed file(s) below for `Vulnerable: <ID>` markers (static Semgrep + `detection-matrix.md` ground truth).

- [`gold-standard-testbed/api_vulnerable.py`](../gold-standard-testbed/api_vulnerable.py)

**Optional HTTP integration tests** (pytest + httpx; require a running API, `HEXVIBE_TARGET_URL`): [`gold-standard-testbed/integration/verify_fastapi_async_poc.py`](../gold-standard-testbed/integration/verify_fastapi_async_poc.py). See [`gold-standard-testbed/integration/README.md`](../gold-standard-testbed/integration/README.md).

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

