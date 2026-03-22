# Devops Security

## Stack overview

See [`patterns.md`](patterns.md) for Anti-Pattern / Safe-Pattern definitions for this domain.

## Top threats

- Map concrete rows from the pattern table to your architecture.

## Pattern catalog

Complete Anti-Pattern / Safe-Pattern definitions live in [`patterns.md`](patterns.md). The table below is a **table of contents** by metric ID.

| ID | Metric | Stack |
|---|---|---|
| `DVS-001` | Dockerfile: Запуск от root (USER root / отсутствие USER) | Создать непривилегированного пользователя (`useradd -m appuser`) и запускать контейнер через `USER appuser`. |
| `DVS-002` | Dockerfile: Теги latest в базовых образах | Фиксировать образ по версии/диджесту (`FROM node:20.12.2`, `FROM alpine@sha256:...`). |
| `DVS-003` | Dockerfile: Секреты в ENV/ARG | Использовать runtime secret injection (Vault/ESO/K8s Secret), исключить секреты из Docker build layers. |
| `DVS-004` | SLSA L1/L2: отсутствует provenance-аттестация сборки | Генерировать provenance-аттестацию (builder, source, digest, timestamp, workflow id) и сохранять ее как обязательный артефакт релиза. |
| `DVS-005` | NIST SSDF: зависимости с известными CVE допускаются в релиз | Блокировать релиз при High/Critical CVE, учитывать результаты Syft/SCA в policy gate и сохранять решение в CI logs. |
| `DVS-006` | Hermetic Builds: внешние сетевые вызовы в build-стадии | sh` |
| `DVS-007` | VEX Filter: CVE не фильтруются по VEX-статусу `not_affected` | При policy-gate учитывать VEX-аттестации; CVE со статусом `not_affected` маркировать как исключение с audit trail. |
| `DVS-008` | Artifact Signing: release-образы публикуются без подписи | Обязательная подпись артефактов (например, cosign), валидация подписи при деплое и хранение attestations. |
| `DVS-009` | Reproducible Build: недетерминированные сборки без проверки повторяемости | Пинning base images/dependencies, deterministic flags и периодическая проверка reproducibility hash между сборками. |
| `CWE-1104` | Use of Unmaintained/Outdated Components in dependency manifests | Обновлять зависимости до поддерживаемых версий (например, `django>=3.2`, `pillow>=10.3.0`) и включать SCA gate в CI. |
| `CWE-798-ALEMBIC-URL` | Hardcoded DB credentials in `alembic.ini` (`sqlalchemy.url`) | Убрать plaintext credentials из `alembic.ini`, использовать env/secret manager и подстановку URL только через защищенный runtime config. |
| `CWE-116-VITE-PROXY-HEADER-FWD` | Unsafe Vite proxy forwarding of sensitive headers (`Host`, `Cookie`) to untrusted upstream | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-427-NSIS-EXEC-RELATIVE` | NSIS execution of external binaries via relative/unquoted paths (`Exec`/`ExecWait`) | Использовать только абсолютные/канонизированные пути в кавычках, проверять подпись/хэш и исключать запуск бинарников из непроверенных относительных путей. |
| `CWE-377-NSIS-OUTPATH-PERM` | Insecure NSIS output path/library attributes in privileged system directories | Избегать записи в системные каталоги без проверки прав/контекста, явно задавать безопасные `SetDefaultLibAttributes` и контролировать install target policy. |
| `DVS-015` | Downloading binaries/scripts without checksum verification (CWE-353) | После скачивания обязательно проверять `sha256sum -c` (или подпись), прерывать pipeline при mismatch. |
| `DVS-016` | `wget | CWE Final Certification |
| `DVS-017` | Dockerfile remote artifact ADD/RUN without expected hash check (CWE-353) | CWE Final Certification |
| `DVS-018` | CI job executes downloaded CLI/plugin from URL directly (CWE-353) | Использовать dependency lockfiles/hashes (`--require-hashes`) и trusted registries вместо direct URL execution. |
| `DVS-019` | Terraform/Ansible bootstrap scripts fetched over network without integrity enforcement ... | Обязательно задавать `checksum`/signature verification и policy-gate, блокирующий unverified bootstrap artifacts. |
| `DVS-020` | Скачивание и выполнение кода без проверки целостности (CWE-494) | Только verified artifacts: hash/signature gate до execute; запрет pipe-to-shell в Dockerfile. |
| `DVS-021` | Подключение зависимостей из untrusted VCS URL без фиксации коммита (CWE-829) | Lockfile + immutable commit refs; policy deny `git+https` без SHA. |

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

