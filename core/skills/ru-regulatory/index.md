# Enterprise Compliance (Regional Controls)

## Stack overview

Enterprise and regional compliance controls for PII logging, data residency and anonymization before foreign AI APIs, certified cryptography in critical infrastructure contexts, and import substitution portability. Metrics are prefixed **`RRC`**.

## Top threats

- Logging PII to stdout or external log systems (`RRC-001`).
- Sending PII to foreign APIs (OpenAI/Claude) without anonymization (`RRC-002`).
- Non-certified / unsafe crypto libraries in the KII contour (`RRC-003`).
- Hardcoded cloud metadata (e.g. AWS IMDS) hurting migration/import substitution (`RRC-004`).

## Pattern catalog

Complete Anti-Pattern / Safe-Pattern definitions live in [`patterns.md`](patterns.md). The table below is a **table of contents** by metric ID.

| ID | Metric | Stack |
|---|---|---|
| `RRC-001` | Enterprise Compliance: PII в stdout / внешние логи | Использовать редактирование/маскирование до логирования (например, `redact_email`, `redact_snils`), а также уровень логов без PII по умолчанию. |
| `RRC-002` | Data Residency: ПДн в зарубежные API без обезличивания | Обезличить/агрегировать ПДн перед отправкой, отделить идентификаторы и payload, добавить контроль/аудит передачи данных. |
| `RRC-003` | GOST: небезопасные/несертифицированные крипто-библиотеки | Использовать сертифицированные средства криптографии / GOST-совместимые библиотеки, соответствующие требованиям контура КИИ. |
| `RRC-004` | Import Substitution: hardcoded cloud metadata | Уйти от hardcoded metadata: использовать абстракции конфигурации/переменные окружения и единый механизм discovery для целевого облака. |
| `RRC-005` | Foreign DNS/NTP | Использовать российские или внутренние корпоративные DNS/NTP резолверы (например, `10.0.0.53`, `ntp.local`). |
| `RRC-006` | Insecure External Repositories | В CI/CD разрешать только доверенные внутренние зеркала/репозитории артефактов (Nexus/Artifactory/internal registry). |
| `RRC-007` | Information Leakage in Errors | Возвращать обобщенное сообщение пользователю; детали и stacktrace писать только во внутренние журналы. |
| `RRC-008` | Missing Security Audit | Централизованно логировать неудачные входы, смену паролей и чувствительные события безопасности (SIEM/audit bus). |
| `RRC-009` | Unsigned binary execution | Перед запуском проверять цифровую подпись/доверенную цепочку и хэш (особенно на критических узлах). |
| `RRC-010` | Insecure Data Deletion | Перед удалением перезаписать файл нулями/случайными данными, затем удалить (`fsync` + `remove`) с учетом политики хранения. |
| `RRC-011` | Banned Functions (Security Policy) | Использовать `subprocess.run([...], shell=False, check=True)` с фиксированным whitelist аргументов. |
| `RRC-012` | Missing Config Integrity Check | Проверять SHA-256/HMAC целостность конфигурации при старте; при mismatch — fail closed и аудит-событие. |
| `RRC-013` | ГОСТ 57580.1 / ЦБ: "мясные" учетки вместо УДИ/УДА токенов | Использовать токены УДИ/УДА (OIDC/OAuth2, client credentials, mTLS-bound tokens), запрет static user/pass в интеграциях и сервис-аккаунтах. |
| `RRC-014` | ЦБ: Недостаточная аутентификация интеграций (нет токен-ротации) | Обязательная короткоживущая токен-модель, ротация, revoke/introspection, аудит выдачи и использования токенов. |
| `RRC-015` | FAPI.SEC/PAOK: запрет Implicit Flow, обязательный Code+PKCE+mTLS | Использовать Authorization Code Flow + PKCE, а для межсервисного взаимодействия включать mTLS (client cert/key) и проверку FAPI-профиля. |
| `RRC-016` | Docker Root: запуск контейнера от root | Явно создавать непривилегированного пользователя и переключаться на него (`RUN useradd -m appuser`, `USER appuser`). |
| `RRC-017` | Vault/ESO: запрет hardcoded Secret, требование ExternalSecret | Использовать `kind: ExternalSecret` (ESO) + backend Vault; исключить plaintext секреты в Git/YAML. |
| `RRC-018` | Tech Stack: запрет drop-технологий в новых сервисах | Для новых микросервисов использовать поддерживаемый стек (Python >= 3.10, без legacy PHP), фиксировать baseline в архитектурном стандарте. |
| `RRC-019` | Клинкер/Keycloak: обязательный auth middleware для внутренних API | Все внутренние API должны проходить через middleware аутентификации Keycloak (`VerifyToken`/аналог), deny-by-default. |
| `RRC-020` | Целостность КИИ: контрольные суммы исполняемых файлов и конфигов перед стартом | Перед запуском проверять SHA-256/ГОСТ-хэш исполняемого файла и критичных конфигов; при mismatch — fail closed и аудит-событие (Приказ 239). |
| `RRC-021` | СЗИ-контроль: отсутствие проверки состояния AV/IDS в контуре | Перед запуском проверять наличие и работоспособность СЗИ (антивирус, IDS/IPS, EDR агент), логировать статус и блокировать старт при критическом отказе. |
| `RRC-022` | SDL/ГОСТ Р 56939: результаты статанализа не фиксируются в логах сборки | Обязательная фиксация результатов SAST/SCA в артефактах CI (лог/отчет), подпись и хранение для аудита SDL по ГОСТ Р 56939. |
| `RRC-023` | Key Rotation: отсутствует `rotation_period` в Vault/KMS политиках | Для криптографических ключей задать и контролировать `rotation_period`, автоматическую ротацию и журналировать события смены ключей. |
| `RRC-024` | Anti-Overlay/Integrity: нет CSP и контроля целостности UI | Включить строгий CSP, SRI для внешних скриптов и проверки целостности DOM/critical forms для защиты ДБО от overlay/injection атак. |
| `RRC-025` | Payment Control: неизменность реквизитов между create и sign не контролируется | Фиксировать hash реквизитов на этапе create и сравнивать перед sign/submit; при несовпадении — reject + audit event. |
| `RRC-026` | Post-Quantum Readiness: отсутствует стратегия крипто-миграции | Вести инвентаризацию криптопримитивов, план гибридных схем и процедуру миграции ключей/сертификатов под PQ-ready профиль. |

## Verification

**Verification:** Check the gold testbed file(s) below for `Vulnerable: <ID>` markers (static Semgrep + `detection-matrix.md` ground truth).

- [`gold-standard-testbed/ru_regulatory_vulnerable.py`](../gold-standard-testbed/ru_regulatory_vulnerable.py)

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

