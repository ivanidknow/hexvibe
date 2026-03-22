# Integration Security

## Stack overview

See [`patterns.md`](patterns.md) for Anti-Pattern / Safe-Pattern definitions for this domain.

## Top threats

- Map concrete rows from the pattern table to your architecture.

## Pattern catalog

Complete Anti-Pattern / Safe-Pattern definitions live in [`patterns.md`](patterns.md). The table below is a **table of contents** by metric ID.

| ID | Metric | Stack |
|---|---|---|
| `ITS-001` | Keycloak JWT: отключена проверка подписи/issuer/audience | Использовать `authlib.jose.JsonWebKey`/`jwt.decode` с `key` из JWKS, явные `claims_options` для `iss`/`aud`; запретить `verify_signature=False`. |
| `ITS-002` | Vault: хардкод секретов/токенов в коде и конфиге | Убрать plaintext: AppRole/K8s auth в Vault; для OAuth-клиентов к внешним IdP использовать `authlib.integrations` (token storage в защищённом хранилище, не в коде). |
| `ITS-003` | K8s интеграции без External Secrets Operator | ESO + backend; секреты для webhook/OAuth подписей хранить в ESO/Vault, не в `stringData`; ключи HMAC для inbound webhooks — через secret reference. |
| `ITS-004` | Circuit Breaker: голые вызовы Клинкера/API без предохранителей | Оборачивать исходящие вызовы в circuit breaker + таймауты; для OAuth2 client credentials к внешним API использовать `authlib.integrations.httpx_client` с лимитами и явной конфигурацией TLS. |
| `ITS-005` | Bulkhead & Timeouts: HTTP-вызовы без timeout и без лимитов пула | `httpx.Client(timeout=..., limits=Limits(...))`; для подписанных исходящих запросов использовать middleware/обёртки с фиксированными лимитами и проверкой сертификата (`verify=True`). |
| `ITS-006` | Retry Storm: без retry budget и jitter | Retry с backoff+jitter и circuit state; не повторять запросы с тем же телом без idempotency-key для небезопасных методов. |
| `ITS-007` | Idempotency Gap: платежные API без idempotency ключей | Заголовок `Idempotency-Key` + серверная дедупликация; для webhook-ответов после обработки — идемпотентная запись по `event_id`. |
| `ITS-008` | Webhook endpoint без проверки HMAC/подписи входящего запроса (CWE-345, CWE-924) | Middleware/FastAPI dependency: проверка подписи до парсинга JSON; Python: `hmac.compare_digest` + секрет из env/ESO; при OAuth/JWS inbound — `authlib.jose` для проверки JWS; Node: `crypto.timingSafeEqual` + express middleware. |
| `ITS-009` | Межсервисный httpx с отключенной проверкой TLS (`verify=False`) | Убрать `verify=False`; задать доверенный bundle/CA; для mTLS — `cert=(client_cert, key)`; OAuth между сервисами — `authlib` + валидный TLS. |
| `ITS-010` | Интеграционный вызов по HTTP без TLS (утечка токена/секрета по сети) | Все вызовы к IdP/partner API — HTTPS; токены через `authlib` OAuth2 session с TLS-only `metadata` URL; не передавать секреты по `http://`. |
| `ITS-011` | Исходящий HTTP-запрос на URL из пользовательского ввода (SSRF в интеграции) | Валидация URL до запроса; для OAuth callbacks использовать зарегистрированные redirect_uri в `authlib` OAuth client. |
| `ITS-012` | OAuth/OIDC `redirect_uri` / `return_to` без строгого allowlist | `authlib` OAuth2 client: фиксированный `redirect_uri`; на сервере — проверка `redirect_uri` против клиентской регистрации. |
| `ITS-013` | Логирование сырого ответа внешнего API с токенами/PII | Structured logging без тел ответов; для отладки OAuth использовать `authlib` tracing hooks без raw tokens. |
| `ITS-014` | Десериализация недоверенного payload от партнёра (pickle) | Только JSON/MessagePack с валидацией; для JWE/JWT — `authlib.jose`. |
| `ITS-015` | Динамический `eval`/`exec` над данными интеграционного вебхука | Парсить JSON в типизированные модели; подпись вебхука (middleware + `authlib`/HMAC) до бизнес-логики. |
| `ITS-016` | `subprocess` с аргументами из payload партнёра/вебхука | После проверки подписи вебхука маппить `action` на фиксированные команды; не передавать raw input в `subprocess`. |
| `ITS-017` | Парсинг XML от партнёра без `defusedxml`/безопасных настроек | Безопасный XML-парсер; для SAML/OIDC metadata — `authlib` loaders с проверкой подписи. |
| `ITS-018` | FastAPI: `Security(oauth2_scheme)` без `scopes` на интеграционном эндпоинте (CWE-285) | Явно задавать `scopes=[...]` в `Security(...)` / `OAuth2AuthorizationCodeBearer(..., scopes=...)`; проверять scope в dependency до бизнес-логики; для machine-to-machine — `authlib.integrations` + зарегистрированные scopes. |
| `ITS-019` | Токен/API-ключ в query/`params` вместо заголовков (CWE-598) | Перенести секреты в headers; для OAuth2 — `authlib` OAuth2 client с token в Authorization; отключить логирование полных URL. |
| `ITS-020` | Nginx/Squid: webhook location без лимита размера тела (CWE-770) | Задать лимит тела для webhook path; комбинировать с таймаутами; для подписанных тел — всё равно ограничивать размер до парсинга. |
| `ITS-021` | JWT/OAuth: время жизни access token > 24h или декод без проверки `iss` (CWE-613) | Короткий access TTL, обязательный `iss`/`aud`; `authlib.jose.JWTClaims` с `claims_options` для issuer. |
| `ITS-022` | SSRF: исходящий запрос к metadata IP `169.254.169.254` (CWE-918) | Единый egress wrapper с denylist IP (169.254.0.0/16, …); `authlib` только для зарегистрированных partner URL. |
| `ITS-023` | SSRF Python: `httpx` к AWS metadata (CWE-918) | Общий egress-клиент с denylist metadata CIDR; `authlib` redirect только на зарегистрированные URI. |
| `ITS-024` | SSRF Python: `urllib` к GCP metadata host (CWE-918) | DNS/IP validation + denylist cloud metadata hostnames. |
| `ITS-025` | SSRF Node: `axios` к Alibaba metadata (CWE-918) | Центральный HTTP-клиент с blocklist облачных metadata адресов. |
| `ITS-026` | SSRF Node: `fetch` к Azure IMDS (CWE-918) | Denylist + SDK вместо raw fetch к IMDS. |
| `ITS-027` | SSRF Python: конкатенация URL с пользовательским путём к metadata (CWE-918) | Строгий URL parser + denylist перед `requests`. |
| `ITS-028` | SSRF JS: IPv6 link-local metadata (CWE-918) | Egress allowlist + блок fd00::/8 для metadata-паттернов. |
| `ITS-029` | SSRF: `httpx.AsyncClient` GET к link-local metadata (CWE-918) | Общий egress wrapper; запретить literal metadata URL в коде приложения. |
| `ITS-030` | SSRF: `axios` instance с `baseURL` на metadata host (CWE-918) | Фабрика HTTP-клиентов с валидацией baseURL против blocklist. |

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

