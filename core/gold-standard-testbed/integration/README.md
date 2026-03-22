# Optional integration tests (HTTP)

These modules were migrated from `skills/*/verify_poc.py`. They run **pytest + httpx** against a **live API** — they are **not** required for the **300-rule** Semgrep / `Vulnerable: <ID>` gold matrix.

## Prerequisite

- Set `HEXVIBE_TARGET_URL` (default `http://127.0.0.1:8000`).
- Start the target application that exposes the routes used in each module.

## Static calibration (source of truth for 300 patterns)

For HexVibe rule IDs, always use **`gold-standard-testbed/`** marker files (e.g. `api_vulnerable.py`, `*_vulnerable.ts`) and `python scripts/sync_semgrep.py` → `detection-matrix.md`.

| Module | Former path (removed from `skills/`) | Notes |
|--------|----------------------------------------|-------|
| [`verify_fastapi_async_poc.py`](verify_fastapi_async_poc.py) | `skills/fastapi-async/verify_poc.py` | Latency, SQLi probe, concurrency |
| [`verify_auth_keycloak_poc.py`](verify_auth_keycloak_poc.py) | `skills/auth-keycloak/verify_poc.py` | Forged JWT probes |
| [`verify_infra_k8s_helm_poc.py`](verify_infra_k8s_helm_poc.py) | `skills/infra-k8s-helm/verify_poc.py` | `/meta/*` runtime hints |
| [`verify_app_logic_poc.py`](verify_app_logic_poc.py) | `skills/app-logic/verify_poc.py` | BOLA, transfers, SSRF business flow |
| [`verify_observability_poc.py`](verify_observability_poc.py) | `skills/observability/verify_poc.py` | Trace IDs, sanitized errors, log injection |

Run (example):

```bash
pip install pytest httpx
set HEXVIBE_TARGET_URL=http://127.0.0.1:8000
pytest gold-standard-testbed/integration/ -q
```
