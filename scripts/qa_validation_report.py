import json
import random
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.adapter import ask_hexvibe_impl


RULES_DIR = ROOT / "core" / "semgrep-rules"
MATRIX_FILE = ROOT / "core" / "gold-standard-testbed" / "detection-matrix.md"
OUTPUT_JSON = ROOT / "core" / "gold-standard-testbed" / "qa-validation-v13.json"

RULE_ID_RE = re.compile(r"id:\s*hexvibe\.[^.]+\.([a-z0-9.\-]+)\s*$", re.MULTILINE)
MATRIX_ROW_RE = re.compile(r"^\|\s*([A-Z0-9]{2,4}-[0-9A-Z.\-]+)\s*\|\s*`([^`]+)`\s*\|\s*([A-Z]+)\s*\|", re.MULTILINE)


def slug_to_metric(slug: str) -> str:
    prefix, rest = slug.split("-", 1)
    return f"{prefix.upper()}-{rest.upper()}"


def collect_expected_ids() -> set[str]:
    ids: set[str] = set()
    for yml in sorted(RULES_DIR.glob("*.yaml")):
        text = yml.read_text(encoding="utf-8")
        for m in RULE_ID_RE.finditer(text):
            ids.add(slug_to_metric(m.group(1)))
    return ids


def collect_matrix_hits() -> dict[str, str]:
    text = MATRIX_FILE.read_text(encoding="utf-8")
    by_id: dict[str, str] = {}
    for m in MATRIX_ROW_RE.finditer(text):
        metric_id = m.group(1)
        marker_file = m.group(2)
        status = m.group(3)
        if status == "HIT":
            by_id[metric_id] = marker_file
    return by_id


def run_rag_stress() -> dict:
    pool = [
        {"query": "GO-033 SQL raw query injection in Go service", "expected_any": ["GO-033", "GO-001", "GO-002"]},
        {"query": "Как в C# убрать BinaryFormatter.Deserialize и RCE риск?", "expected_any": ["CSH-019"]},
        {"query": "FastAPI route без response_model: что делать?", "expected_any": ["PY-020", "FAS-"]},
        {"query": "Squid egress proxy allow all issue", "expected_any": ["SQD-001"]},
        {"query": "Dockerfile runs as root in container", "expected_any": ["DOCK-010", "DOCK-011", "DVS-001"]},
        {"query": "Kubernetes seccomp and AppArmor baseline", "expected_any": ["K8S-016", "K8S-017", "INF-5.6.2"]},
        {"query": "Nginx TLS 1.3 and HSTS hardening", "expected_any": ["NGX-001", "NGX-006", "INF-5.1.2-TLS"]},
        {"query": "React dangerouslySetInnerHTML xss prevention", "expected_any": ["FTS-001"]},
        {"query": "Node.js mass assignment in Model.create(req.body)", "expected_any": ["NJS-026"]},
        {"query": "Как настроить безопасный egress-прокси в Squid и убрать root из Docker?", "expected_any": ["SQD-001", "DOCK-010", "DOCK-011"]},
        {"query": "Kubernetes NetworkPolicy default deny", "expected_any": ["K8S-021", "INF-5.3.1"]},
        {"query": "C# JWT ValidateIssuer and ValidateAudience", "expected_any": ["CSH-025"]},
    ]
    random.seed(13)
    selected = random.sample(pool, 10)

    checks: list[dict] = []
    max_ms = 0.0
    all_relevant = True
    for case in selected:
        t0 = time.perf_counter()
        response = ask_hexvibe_impl(case["query"])
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        max_ms = max(max_ms, elapsed_ms)
        results = response.get("top_safe_patterns", [])
        found_ids = [str(item.get("metric_id", "")) for item in results]
        relevant = False
        for token in case["expected_any"]:
            if token.endswith("-"):
                if any(fid.startswith(token) for fid in found_ids):
                    relevant = True
                    break
            elif token in found_ids:
                relevant = True
                break
        all_relevant = all_relevant and relevant
        checks.append(
            {
                "query": case["query"],
                "elapsed_ms": round(elapsed_ms, 3),
                "expected_any": case["expected_any"],
                "top_ids": found_ids,
                "relevant": relevant,
            }
        )

    return {
        "selected_queries": len(selected),
        "max_elapsed_ms": round(max_ms, 3),
        "all_within_200ms": max_ms <= 200.0,
        "relevance_100pct": all_relevant,
        "checks": checks,
    }


def main() -> None:
    expected = collect_expected_ids()
    matrix_hits = collect_matrix_hits()
    covered = {i for i in expected if i in matrix_hits}
    missing = sorted(expected - covered)

    coverage = {
        "rules_total": len(expected),
        "with_testbed_example": len(covered),
        "missing_examples": len(missing),
        "missing_ids": missing,
        "status": "PASS" if not missing else "FAIL",
    }

    rag = run_rag_stress()

    report = {
        "version": "v13.0 Fortress",
        "coverage_audit": coverage,
        "rag_efficiency": rag,
        "overall_status": "PASS"
        if coverage["status"] == "PASS" and rag["all_within_200ms"] and rag["relevance_100pct"]
        else "FAIL",
    }

    OUTPUT_JSON.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
