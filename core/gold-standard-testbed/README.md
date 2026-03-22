# Gold Standard Testbed

Интенционально уязвимый тестовый корпус для валидации детекторов.
Все уязвимости в коде маркируются комментарием вида:
`Vulnerable: <PATTERN-ID> (<Name>)`.

## Coverage

- Python API anti-patterns: `gold-standard-testbed/api_vulnerable.py`
- YAML infra anti-patterns: `gold-standard-testbed/infra_vulnerable.yaml`
- Browser JS anti-patterns: `gold-standard-testbed/browser_vulnerable.js`
- Дополнительные infra кейсы: `gold-standard-testbed/Dockerfile`, `gold-standard-testbed/nginx.conf`
- Multi-language injection corpus: `gold-standard-testbed/multi_lang_vulnerable/` (`JAVA-*`, `CSH-*`, `GO-*`, `RUBY-*`)
- Django anti-patterns: `gold-standard-testbed/django_vulnerable.py` (`DJA-*`)
- NestJS anti-patterns: `gold-standard-testbed/nestjs_vulnerable.ts` (`NST-*`)
- Advanced Agent & Cloud: `aac_vulnerable.py`, `aac_vulnerable.ts` (`AAC-*`)
- Insight (Electron/VSTO/NSIS): `insight_vulnerable.ts`, `insight_vulnerable.cs` (`INS-*`)
- Cloud & Secrets: `cloud_secrets_vulnerable.py`, `cloud_secrets_vulnerable.yaml` (`SEC-*`)

**Опционально:** HTTP-интеграционные pytest-модули (не входят в матрицу 300 правил) — `gold-standard-testbed/integration/` (см. `integration/README.md`).

Сводка детекторов: **300** правил (генерация из `semgrep-rules/*.yaml`). Полная таблица ID → файл → HIT: `gold-standard-testbed/detection-matrix.md`; краткий JSON: `gold-standard-testbed/detection-summary.json` (обновляется `scripts/generate_detection_matrix.py` в составе `python scripts/sync_semgrep.py`).

## Критичные (сначала)

- [x] `BIZ-001` -> `gold-standard-testbed/api_vulnerable.py` (BOLA)
- [x] `BIZ-011` -> `gold-standard-testbed/api_vulnerable.py` (Business SSRF)
- [x] `BIZ-014` -> `gold-standard-testbed/api_vulnerable.py` (Race Condition)
- [x] `AK-005` -> `gold-standard-testbed/api_vulnerable.py` (Hardcoded Secret)
- [x] `INF-010` -> `gold-standard-testbed/infra_vulnerable.yaml` (Hardcoded Credentials)
- [x] `INF-4.4` -> `gold-standard-testbed/Dockerfile` (Secrets in image metadata)
- [x] `BRW-008` -> `gold-standard-testbed/browser_vulnerable.js` (Browser SSRF)

## Checklist: Pattern ID -> File

### auth-keycloak
- [x] `AK-001` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `AK-002` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `AK-003` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `AK-004` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `AK-005` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `AK-006` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `AK-007` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `AK-008` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `AK-009` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `AK-010` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `AK-011` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `AK-012` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `AK-013` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `AK-014` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `AK-015` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `AK-016` -> `gold-standard-testbed/api_vulnerable.py`

### fastapi-async
- [x] `FAS-001` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `FAS-002` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `FAS-003` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `FAS-004` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `FAS-005` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `FAS-006` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `FAS-007` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `FAS-008` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `FAS-009` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `FAS-010` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `FAS-011` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `FAS-012` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `FAS-013` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `FAS-014` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `FAS-015` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `FAS-016` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `FAS-017` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `FAS-018` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `FAS-019` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `FAS-020` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `FAS-021` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `FAS-022` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `FAS-023` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `FAS-024` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `FAS-025` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `FAS-026` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `FAS-027` -> `gold-standard-testbed/api_vulnerable.py`

### app-logic
- [x] `BIZ-001` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `BIZ-002` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `BIZ-003` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `BIZ-004` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `BIZ-005` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `BIZ-006` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `BIZ-007` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `BIZ-008` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `BIZ-009` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `BIZ-010` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `BIZ-011` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `BIZ-012` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `BIZ-013` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `BIZ-014` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `BIZ-015` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `BIZ-016` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `BIZ-017` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `BIZ-018` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `BIZ-019` -> `gold-standard-testbed/api_vulnerable.py`

### observability
- [x] `LOG-001` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `LOG-002` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `LOG-003` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `LOG-004` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `LOG-005` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `LOG-006` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `LOG-007` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `LOG-008` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `LOG-009` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `LOG-010` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `LOG-011` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `LOG-012` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `LOG-013` -> `gold-standard-testbed/api_vulnerable.py`
- [x] `LOG-014` -> `gold-standard-testbed/api_vulnerable.py`

### browser-agent
- [x] `BRW-001` -> `gold-standard-testbed/browser_vulnerable.js`
- [x] `BRW-002` -> `gold-standard-testbed/browser_vulnerable.js`
- [x] `BRW-003` -> `gold-standard-testbed/browser_vulnerable.js`
- [x] `BRW-004` -> `gold-standard-testbed/browser_vulnerable.js`
- [x] `BRW-005` -> `gold-standard-testbed/browser_vulnerable.js`
- [x] `BRW-006` -> `gold-standard-testbed/browser_vulnerable.js`
- [x] `BRW-007` -> `gold-standard-testbed/browser_vulnerable.js`
- [x] `BRW-008` -> `gold-standard-testbed/browser_vulnerable.js`
- [x] `BRW-009` -> `gold-standard-testbed/browser_vulnerable.js`
- [x] `BRW-010` -> `gold-standard-testbed/browser_vulnerable.js`
- [x] `BRW-011` -> `gold-standard-testbed/browser_vulnerable.js`
- [x] `BRW-012` -> `gold-standard-testbed/browser_vulnerable.js`
- [x] `BRW-013` -> `gold-standard-testbed/browser_vulnerable.js`

### infra-k8s-helm
- [x] `INF-4.1` -> `gold-standard-testbed/Dockerfile`
- [x] `INF-5.10` -> `gold-standard-testbed/infra_vulnerable.yaml`
- [x] `INF-5.2.1` -> `gold-standard-testbed/infra_vulnerable.yaml`
- [x] `INF-5.2.4` -> `gold-standard-testbed/infra_vulnerable.yaml`
- [x] `INF-5.2.5` -> `gold-standard-testbed/infra_vulnerable.yaml`
- [x] `INF-5.3.1` -> `gold-standard-testbed/infra_vulnerable.yaml`
- [x] `INF-2.5.1` -> `gold-standard-testbed/nginx.conf`
- [x] `INF-5.3.2` -> `gold-standard-testbed/nginx.conf`
- [x] `INF-5.3.1-NGX` -> `gold-standard-testbed/nginx.conf`
- [x] `INF-1.2.1` -> `gold-standard-testbed/infra_vulnerable.yaml`
- [x] `INF-1.2.6` -> `gold-standard-testbed/infra_vulnerable.yaml`
- [x] `INF-5.1.1` -> `gold-standard-testbed/infra_vulnerable.yaml`
- [x] `INF-5.6.2` -> `gold-standard-testbed/infra_vulnerable.yaml`
- [x] `INF-1.2.33` -> `gold-standard-testbed/infra_vulnerable.yaml`
- [x] `INF-4.4` -> `gold-standard-testbed/Dockerfile`
- [x] `INF-5.25` -> `gold-standard-testbed/infra_vulnerable.yaml`
- [x] `INF-5.1.2-TLS` -> `gold-standard-testbed/nginx.conf`
- [x] `INF-5.5.1` -> `gold-standard-testbed/nginx.conf`
- [x] `INF-010` -> `gold-standard-testbed/infra_vulnerable.yaml`
- [x] `INF-011` -> `gold-standard-testbed/infra_vulnerable.yaml`
- [x] `INF-012` -> `gold-standard-testbed/infra_vulnerable.yaml`
- [x] `INF-013` -> `gold-standard-testbed/infra_vulnerable.yaml`
- [x] `INF-014` -> `gold-standard-testbed/infra_vulnerable.yaml`

### java-spring
- [x] `JAVA-001`..`JAVA-020` -> `gold-standard-testbed/multi_lang_vulnerable/java_vulnerable.java`

### csharp-dotnet
- [x] `CSH-001`..`CSH-016` -> `gold-standard-testbed/multi_lang_vulnerable/csharp_vulnerable.cs`

### go-core
- [x] `GO-001`..`GO-040` -> `gold-standard-testbed/multi_lang_vulnerable/go_vulnerable.go`

### ruby-rails
- [x] `RUBY-001`..`RUBY-020` -> `gold-standard-testbed/multi_lang_vulnerable/ruby_vulnerable.rb`

### python-django
- [x] `DJA-001`..`DJA-018` -> `gold-standard-testbed/django_vulnerable.py`

### nodejs-nestjs
- [x] `NST-001`..`NST-020` -> `gold-standard-testbed/nestjs_vulnerable.ts`
