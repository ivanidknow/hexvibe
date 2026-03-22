#!/usr/bin/env bash
set -euo pipefail

echo "[hexvibe] semgrep: $(semgrep --version)"
echo "[hexvibe] trufflehog: $(trufflehog --version)"
echo "[hexvibe] syft: $(syft version | head -n 1)"

python3 /app/server/adapter.py --smoke-test

python3 - <<'PY'
from server.adapter import run_check_impl

docker_res = run_check_impl("core/gold-standard-testbed/devops_security_vulnerable.Dockerfile")
ids = set(docker_res.get("semgrep", {}).get("finding_ids", []))
required = {"DVS-001", "DVS-002"}
if not required.issubset(ids):
    raise SystemExit(f"missing Docker detectors: expected {required}, got {ids}")
print(f"[hexvibe] active Docker detectors: {sorted(ids)}")

integr_res = run_check_impl("core/gold-standard-testbed/integration_security_vulnerable.py")
iids = set(integr_res.get("semgrep", {}).get("finding_ids", []))
if "RRC-013" not in iids:
    raise SystemExit(f"missing meat-account detector RRC-013, got {iids}")
print(f"[hexvibe] integration detectors: {sorted(iids)}")
PY

echo "HexVibe Engine: READY"
