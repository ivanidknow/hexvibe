# License Compliance

## Stack overview

Dependency manifest policy for copyleft licenses (AGPL/SSPL), trusted package sources, and SBOM/lockfile evidence for `package.json` / `requirements.txt`. Metrics are prefixed **`LIC`**.

**Verification note:** LIC checks may require running **Syft via Docker/MCP** to produce SBOM (CycloneDX/SPDX) and detect transitive license risk not visible in manifests.

## Top threats

- Direct and transitive copyleft exposure (`LIC-001`, `LIC-002`, `LIC-009`).
- Unknown metadata and untrusted sources in dependency pipeline (`LIC-004`, `LIC-005`).
- Missing CI/SBOM evidence for license governance (`LIC-006`, `LIC-008`).
- Binary artifact license/provenance gaps (`LIC-010`).

## Pattern catalog

Complete Anti-Pattern / Safe-Pattern definitions live in [`patterns.md`](patterns.md). The table below is a **table of contents** by metric ID.

| ID | Metric | Stack |
|---|---|---|
| `LIC-001` | AGPL-3.0 in `package.json` / `requirements.txt` | Заменить AGPL зависимость на совместимую по лицензии (MIT/BSD/Apache-2.0) и проверить транзитивные зависимости (lockfile/SBOM). |
| `LIC-002` | SSPL for hosted/cloud services | Исключить SSPL зависимости в облачном контуре, заменить на permissive варианты и подтвердить лицензионную совместимость (SBOM/scan). |
| `LIC-003` | Unmaintained / deprecated library (> 2 years) | Обновить библиотеку до поддерживаемой версии, либо заменить на альтернативу с активным мейнтейном; фиксировать версии в lockfile. |
| `LIC-004` | Unknown License Metadata | Разрешать только явно идентифицированные SPDX-лицензии; блокировать сборку при `UNKNOWN`/`NOASSERTION`. |
| `LIC-005` | Untrusted Package Source | Использовать только доверенные внутренние registry/mirror и фиксировать источник в CI policy. |
| `LIC-006` | Missing License Gate in CI | Добавить CI gate: `syft` + policy check (block on AGPL/GPL/SSPL according to org policy). |
| `LIC-008` | Missing SBOM Evidence | Генерировать SBOM через `syft` в формате CycloneDX/SPDX и сохранять как артефакт релиза. |
| `LIC-009` | Transitive Copyleft via Syft | Анализировать `syft`-отчет на транзитивные copyleft-лицензии и блокировать релиз до remediation/exception approval. |
| `LIC-010` | Binary-embedded License Risk | Для бинарных зависимостей проверять наличие license metadata/attestation и подтверждать источник/право использования. |
| `LIC-011` | Paladin: NuGet / внешние DLL без проверки целостности (checksum/lockfile) | Enable central package management + lockfile; verify package hashes in CI; verify binary signatures for external DLLs. |

## Verification

**Verification:** Check the gold testbed file(s) below for `Vulnerable: <ID>` markers (static Semgrep + `detection-matrix.md` ground truth).

- [`gold-standard-testbed/license_compliance_vulnerable.py`](../gold-standard-testbed/license_compliance_vulnerable.py)

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

