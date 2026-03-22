# Cloud & Secrets

## Stack overview

Cloud-native secret management and workload hardening across **Kubernetes YAML** and **Python services**: metadata SSRF, IAM/KMS/Vault hygiene, ENV/log leakage, and JWT trust boundaries. Metrics are prefixed **`SEC`**.

**Product alignment:** cloud workload hardening, metadata egress controls, and secret governance must map to SEC metrics before release.

## Top threats

- Metadata SSRF and exposed cloud identity surfaces (`SEC-001`, `SEC-007`).
- Kubernetes workload misconfigurations around secrets and privilege (`SEC-002`–`SEC-005`).
- Secret leakage to logs, endpoints, and CI output (`SEC-006`, `SEC-013`, `SEC-015`).
- JWT/Vault/KMS misuse and missing secret lifecycle controls (`SEC-008`–`SEC-012`, `SEC-014`).

## Pattern catalog

Complete Anti-Pattern / Safe-Pattern definitions live in [`patterns.md`](patterns.md). The table below is a **table of contents** by metric ID.

| ID | Metric | Stack |
|---|---|---|
| `SEC-001` | SSRF to Cloud Metadata API | Блокировать link-local metadata endpoints в egress policy; использовать IMDSv2/metadata proxy с явной авторизацией. |
| `SEC-002` | K8s Secret in ConfigMap | Хранить секреты только в `Secret`/external secrets manager (Vault/KMS), шифровать at-rest и ограничить RBAC. |
| `SEC-003` | Privileged Container | `privileged: false`, `allowPrivilegeEscalation: false`, `runAsNonRoot: true`, минимальные capabilities. |
| `SEC-004` | HostPath Mount of Sensitive Paths | Запретить опасные `hostPath` mounts; использовать CSI/ephemeral volumes с ограниченными правами. |
| `SEC-005` | Service Account Token Auto-Mount | Отключить auto-mount по умолчанию; выдавать токен только workload-ам, которым он необходим. |
| `SEC-006` | ENV Secret Leakage to Logs | Никогда не логировать весь ENV; применять allowlist полей и redaction для секретов. |
| `SEC-007` | Hardcoded Cloud Credentials | Использовать workload identity / IAM role / short-lived STS tokens без hardcode. |
| `SEC-008` | Insecure JWT Validation | Проверять подпись, `issuer`, `audience`, `exp`, `nbf`, `alg` allowlist. |
| `SEC-009` | Vault Token in Plain Config | Хранить Vault auth через AppRole/K8s auth + short-lived token, ротацию и scoped policies; обязательно использовать Vault Agent Injector для автоматической доставки и ротации токенов/секретов в workload. |
| `SEC-010` | Vault TLS Verification Disabled | Всегда `verify=True`, mTLS/CA pinning, запрет insecure transport. |
| `SEC-011` | Unencrypted Secret in Object Storage | Включить SSE-KMS/CMK, ограничить доступ bucket policy и включить audit trail. |
| `SEC-012` | Broad KMS Permissions | Принцип least privilege: ограничить actions/resources и контекст ключей. |
| `SEC-013` | Publicly Exposed Secrets Endpoint | Удалить/закрыть debug endpoints, включить authz + environment gating для non-prod only. |
| `SEC-014` | Missing Secret Rotation Policy | Обязательная ротация секретов/ключей (TTL), автоматизация revoke/renew и контроль просрочки. |
| `SEC-015` | Unsafe Secret in CI Variables | Masked/protected CI variables, secret scanning в pipeline, запрет echo/print секретов. |
| `SEC-016` | External Secrets Operator Required | Использовать `kind: ExternalSecret`, ссылающийся на `SecretStore/ClusterSecretStore` (Vault backend), и исключить хранение секретов в Git. |
| `SEC-017` | Trusted Mounts for DB Passwords | Передавать секреты как файлы через `volumeMounts` (Vault Agent Injector или ESO synced volume), читать пароль из файловой системы, а не из ENV. |

## Verification

**Verification:** Check the gold testbed file(s) below for `Vulnerable: <ID>` markers (static Semgrep + `detection-matrix.md` ground truth).

- [`gold-standard-testbed/cloud_secrets_vulnerable.py`](../gold-standard-testbed/cloud_secrets_vulnerable.py)
- [`gold-standard-testbed/cloud_secrets_vulnerable.yaml`](../gold-standard-testbed/cloud_secrets_vulnerable.yaml)

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

