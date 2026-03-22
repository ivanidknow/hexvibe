import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILLS_DIR = ROOT / "core" / "skills"
MAPPING_FILE = ROOT / "docs" / "OWASP_MAPPING.md"

ID_PATTERN = re.compile(
    r"\b(?:FAS|AK|INF|BRW|BIZ|LOG|JAVA|CSH|GO|RUBY|DJA|NST|AAC|INS|LIC|RRC|SEC)-[0-9A-Za-z.\-]+\b"
)
ROW_ID_PATTERN = re.compile(
    r"\|\s*((?:FAS|AK|INF|BRW|BIZ|LOG|JAVA|CSH|GO|RUBY|DJA|NST|AAC|INS|LIC|RRC|SEC)-[0-9A-Za-z.\-]+)\s*\|"
)


def collect_skill_ids() -> set[str]:
    ids: set[str] = set()
    for md in SKILLS_DIR.glob("*/patterns.md"):
        text = md.read_text(encoding="utf-8")
        ids.update(ROW_ID_PATTERN.findall(text))
    return ids


def collect_mapping_ids() -> set[str]:
    text = MAPPING_FILE.read_text(encoding="utf-8")
    # Avoid greedy matches like `JAVA-001..JAVA-020` being parsed as a single bogus ID.
    ids: set[str] = {x for x in ID_PATTERN.findall(text) if ".." not in x}
    # Expand documentation ranges like `JAVA-001..JAVA-020` or GO-001..GO-040
    range_re = re.compile(r"\b([A-Z]{2,6})-(\d+)\.\.([A-Z]{2,6})-(\d+)\b")
    for a, start_s, b, end_s in range_re.findall(text):
        if a != b:
            continue
        start_i, end_i = int(start_s), int(end_s)
        if end_i < start_i:
            continue
        width = max(len(start_s), len(end_s))
        for n in range(start_i, end_i + 1):
            ids.add(f"{a}-{n:0{width}d}")
    return ids


def main() -> None:
    skill_ids = collect_skill_ids()
    mapping_ids = collect_mapping_ids()

    missing = sorted(mapping_ids - skill_ids)
    unaccounted = sorted(skill_ids - mapping_ids)

    report = {
        "skills_total": len(skill_ids),
        "mapping_total": len(mapping_ids),
        "missing": missing,
        "unaccounted": unaccounted,
        "status": "PASS" if not missing and not unaccounted else "FAIL",
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))

    if missing or unaccounted:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
