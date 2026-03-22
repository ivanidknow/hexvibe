from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "core" / "gold-standard-testbed" / "gap_fill_vulnerable.py"

VULN_RE = re.compile(r"^\s*#\s*Vulnerable:\s*([A-Z0-9]{2,4}-[0-9A-Za-z.\-]+)")
STACK_RE = re.compile(r"^\s*#\s*Stack:\s*(.+)\s*$")


def stack_for_metric(metric_id: str) -> str:
    prefix = metric_id.split("-", 1)[0]
    if prefix in {"PY", "DJA", "FAS"}:
        return "Python"
    if prefix in {"NJS", "NST", "FTS"}:
        return "Node.js/JavaScript"
    if prefix == "GO":
        return "Go"
    if prefix in {"MOB"}:
        return "Flutter"
    if prefix in {"DSK", "INS", "CSH"}:
        return "Electron/Desktop/.NET"
    if prefix in {"K8S", "DOCK", "NGX", "SQD", "INF"}:
        return "Kubernetes/Infra"
    if prefix in {"AK", "RRC", "LIC"}:
        return "Identity/Compliance"
    if prefix in {"APP", "BIZ"}:
        return "Application Logic"
    if prefix in {"LOG"}:
        return "Observability"
    if prefix in {"AAC", "BRW"}:
        return "Agent/Browser"
    if prefix in {"RUBY"}:
        return "Ruby"
    if prefix in {"JAVA"}:
        return "Java"
    if prefix in {"SEC"}:
        return "Cloud/Secrets"
    if prefix in {"ITS", "DVS"}:
        return "Integration/DevOps"
    return "Generic"


def main() -> None:
    lines = TARGET.read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    inserted = 0

    for line in lines:
        m = VULN_RE.match(line)
        if not m:
            out.append(line)
            continue

        metric_id = m.group(1)
        desired = stack_for_metric(metric_id)

        prev = out[-1] if out else ""
        prev_stack = STACK_RE.match(prev)
        if prev_stack:
            if prev_stack.group(1).strip() != desired:
                out[-1] = f"# Stack: {desired}"
            out.append(line)
            continue

        out.append(f"# Stack: {desired}")
        out.append(line)
        inserted += 1

    TARGET.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"inserted_or_updated_stack_comments={inserted}")


if __name__ == "__main__":
    main()
