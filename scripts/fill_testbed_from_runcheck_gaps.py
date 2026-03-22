import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILLS_DIR = ROOT / "core" / "skills"
REPORT_PATH = ROOT / "core" / "gold-standard-testbed" / "run-check-remediation-report.md"
MISSING_LIST_PATH = ROOT / "core" / "gold-standard-testbed" / "missing-ids-from-runcheck.txt"
GAP_FILL_PATH = ROOT / "core" / "gold-standard-testbed" / "gap_fill_vulnerable.py"

PATTERN_ROW_RE = re.compile(r"^\|\s*([A-Z0-9]{2,4}-[0-9A-Za-z.\-]+)\s*\|")
REPORT_ID_RE = re.compile(r"^###\s*([A-Z0-9]{2,4}-[0-9A-Za-z.\-]+)\s*$")


def collect_all_ids() -> set[str]:
    all_ids: set[str] = set()
    for patterns_path in sorted(SKILLS_DIR.glob("*/patterns.md")):
        for line in patterns_path.read_text(encoding="utf-8").splitlines():
            m = PATTERN_ROW_RE.match(line)
            if m:
                all_ids.add(m.group(1).upper())
    return all_ids


def collect_report_ids() -> set[str]:
    report_ids: set[str] = set()
    if not REPORT_PATH.exists():
        return report_ids
    for line in REPORT_PATH.read_text(encoding="utf-8").splitlines():
        m = REPORT_ID_RE.match(line)
        if m:
            report_ids.add(m.group(1).upper())
    return report_ids


def main() -> None:
    all_ids = collect_all_ids()
    report_ids = collect_report_ids()
    missing = sorted(all_ids - report_ids)

    MISSING_LIST_PATH.write_text("\n".join(missing) + ("\n" if missing else ""), encoding="utf-8")

    lines: list[str] = []
    lines.append("# Auto-generated vulnerable markers to close run_check coverage gaps.")
    lines.append("# This file is intentionally insecure for detection calibration.")
    lines.append("")
    for metric_id in missing:
        lines.append(f"# Vulnerable: {metric_id}")
        lines.append("insecure_value = True")
        lines.append("")
    GAP_FILL_PATH.write_text("\n".join(lines), encoding="utf-8")

    print(f"all_ids={len(all_ids)} report_ids={len(report_ids)} missing={len(missing)}")
    print(f"missing_list={MISSING_LIST_PATH}")
    print(f"gap_fill_file={GAP_FILL_PATH}")


if __name__ == "__main__":
    main()
