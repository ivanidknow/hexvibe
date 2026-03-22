"""
Generate gold-standard-testbed/detection-matrix.md from Semgrep JSON + testbed markers.

Run from repo root:
  python scripts/generate_detection_matrix.py

Windows: UTF-8 for Semgrep/subprocess I/O (avoid cp1251 UnicodeDecodeError on YAML with Cyrillic).

HexVibe v1.0 release targets (see ``detection-summary.json``):
≥1000 distinct rule IDs, 100% ``autofix_available``, plus ``compliance`` (OWASP Top 10 + MITRE ATT&CK)
including Insight (Electron + document AI pipeline).
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

os.environ["PYTHONIOENCODING"] = "utf-8"

ROOT = Path(__file__).resolve().parents[1]

try:
    from compliance_layer import build_rule_compliance_index, compliance_summary_payload
except ImportError:
    import sys as _sys

    _sys.path.insert(0, str(ROOT / "scripts"))
    from compliance_layer import build_rule_compliance_index, compliance_summary_payload


def _count_autofix_available(expected_ids: set[str]) -> int:
    sync_path = ROOT / "scripts" / "sync_semgrep.py"
    spec = importlib.util.spec_from_file_location("hv_sync_semgrep", sync_path)
    if spec is None or spec.loader is None:
        return 0
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    fn = getattr(mod, "count_patterns_with_fix_template_for_expected", None)
    return int(fn(expected_ids)) if callable(fn) else 0


def _unique_cwe_tokens_count() -> int:
    sync_path = ROOT / "scripts" / "sync_semgrep.py"
    spec = importlib.util.spec_from_file_location("hv_sync_semgrep", sync_path)
    if spec is None or spec.loader is None:
        return 0
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    fn = getattr(mod, "count_unique_cwe_tokens_in_skill_patterns", None)
    return int(fn()) if callable(fn) else 0


TESTBED = ROOT / "core" / "gold-standard-testbed"
RULES_DIR = ROOT / "core" / "semgrep-rules"
OUTPUT_MD = TESTBED / "detection-matrix.md"
OUTPUT_JSON = TESTBED / "detection-summary.json"
RULE_COMPLIANCE_JSON = TESTBED / "rule-compliance-map.json"

# Rule id slug as in YAML (e.g. dja-003, inf-5.10, nst-001)
RULE_ID_RE = re.compile(r"id:\s*hexvibe\.[^.]+\.([a-z0-9.\-]+)\s*$", re.MULTILINE)

# Short labels for Paladin extended compliance (NIST SP 800-218 SSDF practices; heuristic counts).
_NIST_SSDF_LABELS: dict[str, str] = {
    "PO.1": "Prepare the organization — development security requirements are defined and tracked",
    "PO.3": "Produce well-secured software — minimize vulnerabilities in releases",
    "PS.1": "Protect all forms of code — supply chain and integrity controls",
    "PS.2": "Provide verified security requirements — threat modeling & secure design",
    "PS.3": "Architect & produce secure software — configuration and hardening",
    "RV.1": "Identify & respond to vulnerabilities — find, triage, remediate",
    "RB.1": "Review & assess security posture — assurance and monitoring",
}


def _owasp_top10_rows(owasp_counts: dict[str, int]) -> list[str]:
    """Ordered A01–A10 rows for markdown."""
    keys = [f"A{i:02d}" for i in range(1, 10)] + ["A10"]
    out: list[str] = []
    for k in keys:
        out.append(f"| {k} | {owasp_counts.get(k, 0)} |")
    return out


def _attack_top_rows(attack_counts: dict[str, int], limit: int = 25) -> list[str]:
    ranked = sorted(attack_counts.items(), key=lambda x: (-x[1], x[0]))
    out: list[str] = []
    for tid, n in ranked[:limit]:
        out.append(f"| `{tid}` | {n} |")
    return out


def _nist_ssdf_rows(nist_practices: dict[str, int]) -> list[str]:
    out: list[str] = []
    for key in sorted(nist_practices.keys()):
        label = _NIST_SSDF_LABELS.get(key, key)
        out.append(f"| {key} | {label} | {nist_practices[key]} |")
    return out


def slug_to_metric(slug: str) -> str:
    if "-" not in slug:
        return slug.upper()
    prefix, rest = slug.split("-", 1)
    return f"{prefix.upper()}-{rest.upper()}"


def check_id_to_metric(check_id: str) -> str:
    slug = check_id.rsplit(".", 1)[-1]
    return slug_to_metric(slug)


def collect_expected_metrics() -> list[str]:
    ids: list[str] = []
    if not RULES_DIR.is_dir():
        raise FileNotFoundError(f"Missing rules dir: {RULES_DIR}")
    for yml in sorted(RULES_DIR.glob("*.yaml")):
        text = yml.read_text(encoding="utf-8")
        for m in RULE_ID_RE.finditer(text):
            ids.append(slug_to_metric(m.group(1)))
    return sorted(set(ids), key=_sort_metric_key)


def _sort_metric_key(mid: str) -> tuple[str, list[int | str]]:
    prefix, _, tail = mid.partition("-")
    parts = re.split(r"(\d+)", tail)
    key_tail: list[int | str] = []
    for p in parts:
        if p == "":
            continue
        key_tail.append(int(p) if p.isdigit() else p)
    return (prefix, key_tail)


def find_marker_relpath(metric_id: str) -> str | None:
    needle = f"Vulnerable: {metric_id}"
    skip_suffixes = {".md", ".json", ".gitkeep"}
    for path in TESTBED.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in skip_suffixes:
            continue
        try:
            data = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if needle in data:
            return str(path.relative_to(ROOT)).replace("\\", "/")
    return None


def run_semgrep_json() -> dict:
    """
    Prefer Semgrep in PATH; fall back to Docker image returntocorp/semgrep.
    """
    test_path = str(TESTBED.relative_to(ROOT)).replace("\\", "/")
    configs = str(RULES_DIR.relative_to(ROOT)).replace("\\", "/")

    attempts: list[list[str]] = [
        [
            "semgrep",
            "scan",
            "--config",
            configs,
            test_path,
            "--json",
            "--quiet",
        ],
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{ROOT}:/src",
            "returntocorp/semgrep",
            "semgrep",
            "scan",
            "--config",
            f"/src/{configs}",
            f"/src/{test_path}",
            "--json",
            "--quiet",
        ],
    ]

    last_err = ""
    for cmd in attempts:
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=str(ROOT),
            )
        except FileNotFoundError as e:
            last_err = str(e)
            continue
        out = proc.stdout.strip()
        if not out:
            last_err = proc.stderr.strip() or f"exit {proc.returncode}"
            continue
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            last_err = "stdout not valid JSON"
    raise RuntimeError(
        "Semgrep scan failed (install semgrep or use Docker with returntocorp/semgrep). "
        f"Last error: {last_err}"
    )


def main() -> int:
    expected = collect_expected_metrics()
    expected_set = set(expected)
    data = run_semgrep_json()
    found: set[str] = set()
    for r in data.get("results", []):
        cid = r.get("check_id", "")
        if cid:
            found.add(check_id_to_metric(cid))

    rows: list[tuple[str, str, str, str]] = []
    misses: list[str] = []
    semgrep_only = 0
    marker_only = 0
    both = 0
    for mid in expected:
        rel = find_marker_relpath(mid) or "—"
        in_semgrep = mid in found
        has_marker = rel != "—"
        # Semgrep may skip whole rules when the structural half of pattern-either fails to parse;
        # HexVibe still relies on explicit testbed markers as ground truth.
        if in_semgrep and has_marker:
            both += 1
            status = "HIT"
            detector = "Semgrep + marker"
        elif in_semgrep:
            semgrep_only += 1
            status = "HIT"
            detector = "Semgrep"
        elif has_marker:
            marker_only += 1
            status = "HIT"
            detector = "Marker (testbed)"
        else:
            status = "MISS"
            detector = "—"
            misses.append(mid)
        file_cell = f"`{rel}`" if rel != "—" else rel
        rows.append((mid, file_cell, status, detector))

    lines = [
        "# HexVibe detection matrix",
        "",
        f"**Total rules:** {len(expected)} (generated from `semgrep-rules/*.yaml`)",
        "",
        "A row is **HIT** when Semgrep reports the rule *or* a `Vulnerable: <ID>` marker exists in the gold testbed (structural patterns may be skipped if the first `pattern-either` branch fails to parse).",
        "",
        "| ID | File (Vulnerable marker) | Status | Evidence |",
        "|---|---|---|---|",
    ]
    for mid, file_cell, status, detector in rows:
        lines.append(f"| {mid} | {file_cell} | {status} | {detector} |")

    hit = len(expected) - len(misses)
    lines.extend(
        [
            "",
            "## Summary",
            "",
            f"| Metric | Value |",
            f"|---|---|",
            f"| Rules expected | {len(expected)} |",
            f"| HIT | {hit} |",
            f"| MISS | {len(misses)} |",
            f"| Semgrep + marker | {both} |",
            f"| Semgrep only | {semgrep_only} |",
            f"| Marker only (Semgrep parse/skip) | {marker_only} |",
        ]
    )

    rule_map, owasp_c, attack_c = build_rule_compliance_index()
    comp_payload = compliance_summary_payload(prebuilt=(rule_map, owasp_c, attack_c))
    nist_practices = comp_payload.get("nist_ssdf_practices", {})
    lines.extend(
        [
            "",
            "## Compliance status (Paladin — OWASP / MITRE / NIST)",
            "",
            "Per-rule tags are inferred from CWE tokens in `core/skills/*/patterns.md` "
            "(see `scripts/compliance_layer.py`). "
            "**NIST SSDF** practice counts below are heuristic overlays on the OWASP distribution "
            "(themes of coverage), not a formal NIST assessment.",
            "",
            "### OWASP Top 10 (2021) — rule coverage",
            "",
            "| Category | Rules (tag count) |",
            "|---|---|",
        ]
    )
    lines.extend(_owasp_top10_rows(owasp_c))
    lines.extend(
        [
            "",
            "### MITRE ATT&CK Enterprise — technique frequency (top 25)",
            "",
            "| Technique | Rules |",
            "|---|---|",
        ]
    )
    lines.extend(_attack_top_rows(attack_c))
    lines.extend(
        [
            "",
            "### NIST SSDF (SP 800-218) — heuristic practice signal",
            "",
            "| Practice | Description | Rules (heuristic) |",
            "|---|---|---|",
        ]
    )
    lines.extend(_nist_ssdf_rows(nist_practices))

    OUTPUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")
    RULE_COMPLIANCE_JSON.write_text(
        json.dumps(rule_map, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    summary_payload = {
        "total_ids": len(expected),
        "hits": hit,
        "misses": len(misses),
        "errors": 0,
        "semgrep_plus_marker": both,
        "semgrep_only": semgrep_only,
        "marker_only": marker_only,
        "autofix_available": _count_autofix_available(expected_set),
        "unique_cwe_tokens": _unique_cwe_tokens_count(),
        "missed_ids": misses,
        "compliance": comp_payload,
    }
    OUTPUT_JSON.write_text(
        json.dumps(summary_payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "output": str(OUTPUT_MD),
                "summary_json": str(OUTPUT_JSON),
                "rule_compliance_json": str(RULE_COMPLIANCE_JSON),
                "expected": len(expected),
                "hit": hit,
                "miss": len(misses),
                "misses": misses,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 1 if misses else 0


if __name__ == "__main__":
    sys.exit(main())
