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
| `FAS-008` | Global Client Reuse: создание `AsyncClient`/DB-коннекта внутри хендлера (Logic: strong) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
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
| `FAS-020` | Async Context Leakage: dependency без `yield/finally` не закрывает ресурсы (Logic: strong) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
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
| `V13F-001` | ASVS V13 Compliance: FastAPI endpoint lacks strict `Content-Type` enforcement (Complian... | Compliance: ASVS-V13 |
| `V13F-002` | ASVS V13 Compliance: unexpected charset accepted for JSON body (Compliance: ASVS-V13) | Compliance: ASVS-V13 |
| `V13F-003` | ASVS V13 Compliance: request parser auto-fallback from invalid content type (Compliance... | Compliance: ASVS-V13 |
| `V13F-004` | ASVS V13 Compliance: Pydantic model allows unknown fields by default (Compliance: ASVS-... | Compliance: ASVS-V13 |
| `V13F-005` | ASVS V13 Compliance: nested DTOs miss `extra="forbid"` (Compliance: ASVS-V13) | Compliance: ASVS-V13 |
| `V13F-006` | ASVS V13 Compliance: PATCH accepts arbitrary dict merged into entity (Compliance: ASVS-... | Compliance: ASVS-V13 |
| `V13F-007` | ASVS V13 Compliance: response missing `X-Content-Type-Options: nosniff` (Compliance: AS... | Compliance: ASVS-V13 |
| `V13F-008` | ASVS V13 Compliance: response missing strict CSP for docs/static (Compliance: ASVS-V13) | Compliance: ASVS-V13 |
| `V13F-009` | ASVS V13 Compliance: HTTPS API missing HSTS header (Compliance: ASVS-V13) | Compliance: ASVS-V13 |
| `V13F-010` | ASVS V13 Compliance: header middleware bypass for exception responses (Compliance: ASVS... | Compliance: ASVS-V13 |
| `V13F-011` | ASVS V13 Compliance: OpenAPI JSON served with permissive media negotiation (Compliance:... | Compliance: ASVS-V13 |
| `V13F-012` | ASVS V13 Compliance: file upload endpoint accepts JSON unexpectedly (Compliance: ASVS-V13) | Compliance: ASVS-V13 |
| `V13F-013` | ASVS V13 Compliance: schema validation disabled for speed on critical endpoint (Complia... | Compliance: ASVS-V13 |
| `V13F-014` | ASVS V13 Compliance: custom decoder accepts duplicate keys silently (Compliance: ASVS-V13) | Compliance: ASVS-V13 |
| `V13F-015` | ASVS V13 Compliance: untyped `Any` fields in auth-sensitive DTOs (Compliance: ASVS-V13) | Compliance: ASVS-V13 |
| `V13F-016` | ASVS V13 Compliance: endpoint consumes both form and JSON without separation (Complianc... | Compliance: ASVS-V13 |
| `V13F-017` | ASVS V13 Compliance: gateway/proxy strips app-set CSP/HSTS headers (Compliance: ASVS-V13) | Compliance: ASVS-V13 |
| `V13F-018` | ASVS V13 Compliance: no `additionalProperties=false` equivalent for query-object parser... | Compliance: ASVS-V13 |
| `V13F-019` | ASVS V13 Compliance: response content-type mismatch in exception handler (Compliance: A... | Compliance: ASVS-V13 |
| `V13F-020` | ASVS V13 Compliance: no centralized V13 policy test for API headers/content rules (Comp... | Compliance: ASVS-V13 |
| `PYX-201` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-202` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-203` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-204` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-205` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-206` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-207` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-208` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-209` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-210` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-211` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-212` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-213` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-214` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-215` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-216` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-217` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-218` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-219` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-220` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-221` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-222` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-223` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-224` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-225` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-226` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-227` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-228` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-229` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-230` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-231` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-232` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-233` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-234` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-235` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-236` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-237` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-238` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-239` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-240` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-241` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-242` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-243` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-244` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-245` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-246` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-247` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-248` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-249` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-250` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-251` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-252` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-253` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-254` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-255` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-256` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-257` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-258` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-259` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-260` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-261` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-262` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-263` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-264` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-265` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-266` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-267` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-268` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-269` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-270` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-271` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-272` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-273` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-274` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-275` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-276` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-277` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-278` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-279` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-280` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-281` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-282` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-283` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-284` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-285` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-286` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-287` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-288` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-289` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-290` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-291` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-292` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-293` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-294` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-295` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-296` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-297` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-298` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-299` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-300` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-301` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-302` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-303` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-304` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-305` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-306` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-307` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-308` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-309` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-310` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-311` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-312` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-313` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-314` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-315` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-316` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-317` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-318` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-319` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-320` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-321` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-322` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-323` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-324` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-325` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-326` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-327` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-328` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-329` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-330` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-331` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-332` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-333` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-334` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-335` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-336` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-337` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-338` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-339` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-340` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-341` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-342` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-343` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-344` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-345` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-346` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-347` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-348` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-349` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-350` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-351` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-352` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-353` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-354` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-355` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-356` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-357` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-358` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-359` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-360` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-361` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-362` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-363` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-364` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-365` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-366` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-367` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-368` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-369` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-370` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-371` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-372` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-373` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-374` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-375` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-376` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-377` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-378` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-379` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-380` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-381` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-382` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-383` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-384` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-385` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-386` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-387` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-388` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-389` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-390` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-391` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-392` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-393` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-394` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-395` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-396` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-397` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-398` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-399` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-400` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-401` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-402` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-403` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-404` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-405` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-406` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-407` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-408` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-409` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-410` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-411` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-412` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-413` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-414` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-415` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `PYX-416` | FastAPI Depends auth bypass on object route (Logic: strong) | Autofix: enforce owner-scoped query in Depends chain and deny by default. |
| `PYX-417` | Django mass assignment via ModelForm fields = __all__ (Logic: strong) | Autofix: replace broad field binding with explicit allowlist fields. |
| `PYX-418` | Celery untrusted deserialization of task payload | Autofix: replace pickle with JSON and validate schema before use. |
| `PYX-419` | Django ORM filter built from raw user field (IDOR logic: strong) | Autofix: bind ORM queries to authenticated principal instead of user-supplied IDs. |
| `PYX-420` | FastAPI insecure dynamic object merge into domain model | Autofix: introduce field allowlist before model mutation. |
| `IFF-001` | Python/FastAPI: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-002` | Python/FastAPI: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-003` | Python/FastAPI: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-004` | Python/FastAPI: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-005` | Python/FastAPI: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-006` | Python/FastAPI: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-007` | Python/FastAPI: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-008` | Python/FastAPI: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-009` | Python/FastAPI: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-010` | Python/FastAPI: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-011` | Python/FastAPI: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-012` | Python/FastAPI: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-013` | Python/FastAPI: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-014` | Python/FastAPI: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-015` | Python/FastAPI: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-016` | Python/FastAPI: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-017` | Python/FastAPI: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-018` | Python/FastAPI: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-019` | Python/FastAPI: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-020` | Python/FastAPI: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-021` | Python/FastAPI: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-022` | Python/FastAPI: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-023` | Python/FastAPI: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-024` | Python/FastAPI: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-025` | Python/FastAPI: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-026` | Python/FastAPI: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-027` | Python/FastAPI: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-028` | Python/FastAPI: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-029` | Python/FastAPI: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-030` | Python/FastAPI: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-031` | Python/FastAPI: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-032` | Python/FastAPI: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-033` | Python/FastAPI: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-034` | Python/FastAPI: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-035` | Python/FastAPI: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-036` | Python/FastAPI: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-037` | Python/FastAPI: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-038` | Python/FastAPI: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-039` | Python/FastAPI: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-040` | Python/FastAPI: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-041` | Python/FastAPI: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-042` | Python/FastAPI: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-043` | Python/FastAPI: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-044` | Python/FastAPI: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-045` | Python/FastAPI: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-046` | Python/FastAPI: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-047` | Python/FastAPI: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-048` | Python/FastAPI: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-049` | Python/FastAPI: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFF-050` | Python/FastAPI: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `FAS-036` | OWASP Benchmark Python: Path Traversal (CWE-22) | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `FAS-037` | OWASP Benchmark Python: Cross-Site Scripting (XSS) (CWE-79) | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `FAS-038` | OWASP Benchmark Python: SQL Injection (CWE-89) | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `FAS-039` | OWASP Benchmark Python: LDAP Injection (CWE-90) | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `FAS-040` | OWASP Benchmark Python: Weak Hash (CWE-328) | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `FAS-041` | OWASP Benchmark Python: Weak Randomness (CWE-330) | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `FAS-042` | OWASP Benchmark Python: Trust Boundary Violation (CWE-501) | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `FAS-043` | OWASP Benchmark Python: Open Redirect (CWE-601) | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `FAS-044` | OWASP Benchmark Python: XML External Entity (XXE) (CWE-611) | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `FAS-045` | OWASP Benchmark Python: Insecure Cookie (CWE-614) | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `FAS-046` | OWASP Benchmark Python: XPath Injection (CWE-643) | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |

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

