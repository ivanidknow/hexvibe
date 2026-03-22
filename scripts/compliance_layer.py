"""
Infer OWASP Top 10 (2021) and MITRE ATT&CK (Enterprise) tags from CWE tokens in skill patterns.

Used by ``generate_detection_matrix.py`` and optionally by ``server/adapter.py``.
Schema: ``owasp:A01`` … ``owasp:A10``, ``attack:Txxxx`` (string IDs, not full MITRE coverage).
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
SKILLS_DIR = _REPO_ROOT / "core" / "skills"
_CWE_RE = re.compile(r"CWE-(\d+)")
_METRIC_ID_RE = re.compile(r"^[A-Z0-9]{2,4}-[0-9][0-9A-Za-z.\-]*$")

# Primary OWASP Top 10 2021 category per CWE (first match wins in multi-tag aggregation)
CWE_TO_OWASP_2021: dict[int, str] = {
    22: "A01",
    23: "A01",
    285: "A01",
    639: "A01",
    425: "A01",
    862: "A01",
    863: "A01",
    269: "A01",
    311: "A02",
    312: "A02",
    319: "A02",
    326: "A02",
    327: "A02",
    328: "A02",
    330: "A02",
    347: "A08",
    79: "A03",
    89: "A03",
    78: "A03",
    77: "A03",
    94: "A03",
    917: "A03",
    20: "A04",
    657: "A04",
    16: "A05",
    2: "A05",
    15: "A05",
    1104: "A06",
    937: "A06",
    502: "A08",
    353: "A08",
    287: "A07",
    306: "A07",
    613: "A07",
    640: "A07",
    798: "A07",
    345: "A08",
    924: "A08",
    117: "A09",
    532: "A09",
    778: "A09",
    200: "A10",
    201: "A10",
    209: "A10",
    918: "A10",
    441: "A10",
    377: "A05",
    428: "A05",
    367: "A04",
    1254: "A02",
    1256: "A04",
    131: "A04",
    124: "A04",
    125: "A04",
    1311: "A04",
    1333: "A04",
    1336: "A04",
    611: "A03",
    1236: "A03",
    409: "A09",
    1027: "A03",
    1109: "A04",
    749: "A03",
    307: "A07",
}

# Representative MITRE ATT&CK Enterprise techniques (not exhaustive CWE↔T mapping)
CWE_TO_ATTACK: dict[int, list[str]] = {
    918: ["T1190"],
    89: ["T1190"],
    78: ["T1059", "T1059.004"],
    77: ["T1059"],
    94: ["T1059", "T1059.004", "T1059.007"],
    502: ["T1204", "T1055"],
    287: ["T1078", "T1110"],
    306: ["T1078"],
    613: ["T1078", "T1550"],
    798: ["T1552"],
    200: ["T1005"],
    201: ["T1005"],
    209: ["T1005"],
    311: ["T1005"],
    312: ["T1005"],
    377: ["T1078", "T1552"],
    428: ["T1204", "T1548"],
    347: ["T1195", "T1195.001"],
    1104: ["T1195"],
    353: ["T1195"],
    345: ["T1556"],
    924: ["T1556"],
    285: ["T1098"],
    862: ["T1098"],
    1254: ["T1110"],
    532: ["T1562"],
    117: ["T1562"],
    79: ["T1189"],
    20: ["T1190", "T1189"],
    611: ["T1190"],
    1236: ["T1059"],
    409: ["T1499"],
    1027: ["T1059"],
    1109: ["T1190"],
    749: ["T1059", "T1204"],
    307: ["T1110"],
    22: ["T1083"],
}


def _default_owasp_for_skill(skill_dir: str) -> str:
    if "auth" in skill_dir or "access" in skill_dir:
        return "A07"
    if "infra" in skill_dir or "devops" in skill_dir or "platform" in skill_dir:
        return "A05"
    if "agent" in skill_dir or "browser" in skill_dir:
        return "A10"
    if "observability" in skill_dir:
        return "A09"
    if "license" in skill_dir or "compliance" in skill_dir:
        return "A06"
    return "A04"


def _default_attack_for_owasp(owasp: str) -> list[str]:
    return {
        "A01": ["T1098"],
        "A02": ["T1552"],
        "A03": ["T1190"],
        "A04": ["T1190"],
        "A05": ["T1190"],
        "A06": ["T1195"],
        "A07": ["T1078"],
        "A08": ["T1195"],
        "A09": ["T1562"],
        "A10": ["T1190"],
    }.get(owasp, ["T1190"])


def extract_cwe_numbers_from_source(source: str) -> list[int]:
    out: list[int] = []
    for m in _CWE_RE.finditer(source or ""):
        out.append(int(m.group(1)))
    return out


def compliance_for_cwes(cwe_nums: list[int], skill_dir: str) -> tuple[list[str], list[str]]:
    owasp_tags: list[str] = []
    attack_tags: list[str] = []
    if not cwe_nums:
        d = _default_owasp_for_skill(skill_dir)
        owasp_tags.append(f"owasp:{d}")
        for t in _default_attack_for_owasp(d):
            attack_tags.append(f"attack:{t}")
        return owasp_tags, attack_tags
    seen_o: set[str] = set()
    seen_a: set[str] = set()
    for n in cwe_nums:
        o = CWE_TO_OWASP_2021.get(n)
        if o:
            tag = f"owasp:{o}"
            if tag not in seen_o:
                seen_o.add(tag)
                owasp_tags.append(tag)
        for t in CWE_TO_ATTACK.get(n, []):
            tag = f"attack:{t}"
            if tag not in seen_a:
                seen_a.add(tag)
                attack_tags.append(tag)
    if not owasp_tags:
        d = _default_owasp_for_skill(skill_dir)
        owasp_tags.append(f"owasp:{d}")
    if not attack_tags:
        for t in _default_attack_for_owasp(owasp_tags[0].split(":")[1]):
            attack_tags.append(f"attack:{t}")
    return owasp_tags, attack_tags


def build_rule_compliance_index() -> tuple[dict[str, dict[str, list[str]]], dict[str, int], dict[str, int]]:
    """
    Scan ``core/skills/*/patterns.md`` and return:
    - per-metric-id map: { "CSH-001": { "cwe": [...], "owasp": [...], "attack": [...] } } (lists of tag strings)
    - owasp_counts: { "A01": n, ... } without ``owasp:`` prefix
    - attack_counts: { "T1190": n, ... } without ``attack:`` prefix
    """
    rule_map: dict[str, dict[str, list[str]]] = {}
    owasp_counts: dict[str, int] = {}
    attack_counts: dict[str, int] = {}

    for md_path in sorted(SKILLS_DIR.glob("**/patterns.md")):
        skill = md_path.parent.name
        for raw in md_path.read_text(encoding="utf-8").splitlines():
            if not raw.strip().startswith("|"):
                continue
            line_wo = re.sub(r"\s*<!--\s*semantic_anchor:.*?-->\s*$", "", raw, flags=re.I)
            cols = [c.strip() for c in line_wo.strip().split("|")[1:-1]]
            if len(cols) < 5:
                continue
            mid = cols[0]
            if not _METRIC_ID_RE.match(mid):
                continue
            source_idx = 5 if len(cols) >= 6 else 4
            source = cols[source_idx] if source_idx < len(cols) else ""
            cwes = extract_cwe_numbers_from_source(source)
            cwe_strs = [f"CWE-{n}" for n in cwes]
            ow_list, at_list = compliance_for_cwes(cwes, skill)
            if mid in rule_map:
                continue
            rule_map[mid] = {"cwe": cwe_strs, "owasp": ow_list, "attack": at_list}
            for o in ow_list:
                k = o.replace("owasp:", "")
                owasp_counts[k] = owasp_counts.get(k, 0) + 1
            for a in at_list:
                k = a.replace("attack:", "")
                attack_counts[k] = attack_counts.get(k, 0) + 1

    return rule_map, owasp_counts, attack_counts


def compliance_summary_payload(
    prebuilt: tuple[dict[str, dict[str, list[str]]], dict[str, int], dict[str, int]]
    | None = None,
) -> dict[str, object]:
    """
    Aggregate counts for detection-summary.json and Paladin-style compliance tables.

    NIST SSDF (SP 800-218) practice counts are *heuristic overlays* on OWASP-tagged rules:
    they summarize coverage themes, not a formal NIST assessment.
    """
    rule_map, ow, at = (
        prebuilt if prebuilt is not None else build_rule_compliance_index()
    )
    n_rules = len(rule_map)
    # Heuristic mapping: OWASP categories → SSDF practices (PO / PS / RV / RB)
    nist_ssdf: dict[str, int] = {
        # Prepare the Organization
        "PO.1": n_rules,
        "PO.3": ow.get("A06", 0) + ow.get("A08", 0) + ow.get("A05", 0),
        # Protect the Software
        "PS.1": ow.get("A02", 0) + ow.get("A04", 0),
        "PS.2": ow.get("A03", 0) + ow.get("A01", 0),
        "PS.3": ow.get("A05", 0) + ow.get("A09", 0),
        # Respond to Vulnerabilities
        "RV.1": ow.get("A06", 0) + ow.get("A09", 0),
        # Review & Assessment
        "RB.1": ow.get("A10", 0) + ow.get("A09", 0),
    }
    return {
        "schema_version": "paladin-2",
        "owasp_top10_2021": ow,
        "mitre_attack_enterprise": at,
        "rules_with_compliance_tags": n_rules,
        "nist_ssdf_po": {
            "PO.1": n_rules,
            "PO.3": ow.get("A06", 0) + ow.get("A08", 0),
        },
        "nist_ssdf_practices": nist_ssdf,
    }
