"""
Generate gold-standard-testbed files for patterns missing ``Vulnerable: <ID>`` markers.

Routing under ``core/gold-standard-testbed/auto_generated/``:
  - ``vulture/<skill>/``   — VUL-CVE-*
  - ``nova/<skill>/``      — NOV-CWE-*
  - ``juliet/<skill>/``    — HFT-* rows whose title contains ``Juliet``
  - ``scanners/<skill>/``  — all other metric IDs (CSH-*, DVS-*, FAS-*, …)

Each file contains the Anti-Pattern body from ``patterns.md`` (or a minimal placeholder)
plus a language-appropriate marker comment, e.g. ``// Vulnerable: CSH-001``.

Run from repo root:
  python scripts/fill_testbed.py
  python scripts/fill_testbed.py --dry-run
  python scripts/fill_testbed.py --only-legacy   # VUL + NOV + Juliet only (old behaviour)
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS_DIR = ROOT / "core" / "skills"
TESTBED = ROOT / "core" / "gold-standard-testbed"
OUTPUT_ROOT = TESTBED / "auto_generated"

SKIP_SUFFIXES = {".md", ".json", ".gitkeep"}

_SYNC_PATH = ROOT / "scripts" / "sync_semgrep.py"
_spec = importlib.util.spec_from_file_location("hv_sync_semgrep", _SYNC_PATH)
if _spec is None or _spec.loader is None:
    raise RuntimeError(f"Cannot load {_SYNC_PATH}")
_sync = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_sync)

_split_md_table_cells = _sync._split_md_table_cells
_unescape_md_cell = _sync._unescape_md_cell
_strip_cell_wrapping = _sync._strip_cell_wrapping
_md_cell_to_text = _sync._md_cell_to_text
_METRIC_ID_RE = _sync._METRIC_ID_RE
_MISSING = "N/A"

SKILL_DEFAULT_EXT: dict[str, str] = {
    "fastapi-async": ".py",
    "hft-cpp-security": ".cpp",
    "go-core": ".go",
    "integration-security": ".py",
    "java-spring": ".java",
    "java-enterprise": ".java",
    "nodejs-nestjs": ".ts",
    "nodejs-security": ".js",
    "ruby-rails": ".rb",
    "php-security": ".php",
    "rust-security": ".rs",
    "csharp-dotnet": ".cs",
    "python-django": ".py",
    "python-security": ".py",
    "python-backend-pro": ".py",
    "mobile-flutter": ".dart",
    "mobile-security": ".kt",
    "ds-ml-security": ".py",
    "frontend-react": ".tsx",
    "frontend-security": ".js",
    "cloud-secrets": ".py",
    "devops-security": ".dockerfile",
    "infra-k8s-helm": ".yaml",
    "auth-keycloak": ".java",
    "browser-agent": ".py",
    "app-logic": ".py",
    "observability": ".py",
    "advanced-agent-cloud": ".py",
    "desktop-vsto-suite": ".cs",
    "desktop-electron-pro": ".js",
    "license-compliance": ".txt",
    "ru-regulatory": ".yaml",
    "domain-access-management": ".py",
    "domain-data-privacy": ".py",
    "domain-input-validation": ".py",
    "domain-platform-hardening": ".yaml",
}

COMMENT_STYLE: dict[str, str] = {
    ".py": "#",
    ".rb": "#",
    ".yaml": "#",
    ".yml": "#",
    ".sh": "#",
    ".tf": "#",
    ".dockerfile": "#",
    ".txt": "#",
    ".java": "//",
    ".cpp": "//",
    ".c": "//",
    ".h": "//",
    ".hpp": "//",
    ".go": "//",
    ".js": "//",
    ".ts": "//",
    ".tsx": "//",
    ".cs": "//",
    ".php": "//",
    ".rs": "//",
    ".dart": "//",
    ".kt": "//",
}

FALLBACK_BODY: dict[str, str] = {
    ".py": "insecure_value = True\n",
    ".rb": "insecure_value = true\n",
    ".java": "class Insecure { boolean flag = true; }\n",
    ".cpp": "int insecure = 1;\n",
    ".c": "int insecure = 1;\n",
    ".go": "var insecure = true\n",
    ".js": "const insecure = true;\n",
    ".ts": "const insecure: boolean = true;\n",
    ".tsx": "const insecure = true;\n",
    ".cs": "var insecure = true;\n",
    ".php": "$insecure = true;\n",
    ".rs": "let insecure = true;\n",
    ".dart": "var insecure = true;\n",
    ".kt": "val insecure = true\n",
    ".yaml": "insecure: true\n",
    ".dockerfile": "USER root\n",
    ".tf": "resource \"null_resource\" \"insecure\" {}\n",
    ".txt": "insecure\n",
}


def _slug(metric_id: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", metric_id.lower()).strip("_")


def _family(metric_id: str, title: str) -> str:
    if metric_id.startswith("VUL-CVE-"):
        return "vulture"
    if metric_id.startswith("NOV-CWE-"):
        return "nova"
    if metric_id.startswith("HFT-") and "Juliet" in title:
        return "juliet"
    return "scanners"


def _is_legacy_target(metric_id: str, title: str, *, include_juliet: bool) -> bool:
    if metric_id.startswith("VUL-CVE-") or metric_id.startswith("NOV-CWE-"):
        return True
    if include_juliet and metric_id.startswith("HFT-") and "Juliet" in title:
        return True
    return False


def _infer_extension(skill: str, stack: str, anti_text: str) -> str:
    s = (stack or "").lower()
    if "docker" in s or "dockerfile" in s:
        return ".dockerfile"
    if any(k in s for k in ("python", "fastapi", "django", "flask")):
        return ".py"
    if any(k in s for k in ("c/c++", "c++", "cpp", "hft")):
        return ".cpp"
    if "java" in s or "spring" in s:
        return ".java"
    if "go" in s:
        return ".go"
    if "ruby" in s or "rails" in s:
        return ".rb"
    if "typescript" in s or "nestjs" in s:
        return ".ts"
    if "javascript" in s or "node" in s or "electron" in s:
        return ".js"
    if "kotlin" in s:
        return ".kt"
    if "php" in s:
        return ".php"
    if "rust" in s:
        return ".rs"
    if "csharp" in s or ".net" in s or "c#" in s:
        return ".cs"
    if "dart" in s or "flutter" in s:
        return ".dart"
    if any(k in s for k in ("yaml", "helm", "k8s", "kubernetes", "infra")):
        return ".yaml"
    if "terraform" in s or "tf" in s:
        return ".tf"
    head = (anti_text or "").lstrip()[:300]
    if head.startswith(("@", "def ", "class ", "import ", "async def ", "#")):
        return ".py"
    if re.search(r"\b(public|private|protected)\s+class\b", head):
        return ".java"
    if re.search(r"\b(namespace|using)\s+", head) and ";" in head:
        return ".cs"
    if "package " in head and "func " in head:
        return ".go"
    if head.startswith("FROM ") or "FROM " in head[:40]:
        return ".dockerfile"
    return SKILL_DEFAULT_EXT.get(skill, ".txt")


def _marker_line(ext: str, metric_id: str) -> str:
    sym = COMMENT_STYLE.get(ext, "#")
    return f"{sym} Vulnerable: {metric_id}"


def _parse_row_stack(cols: list[str]) -> str:
    if len(cols) >= 6:
        return _strip_cell_wrapping(cols[4])
    if len(cols) >= 5:
        return _strip_cell_wrapping(cols[4])
    return ""


def iter_patterns(*, include_all: bool, include_juliet: bool) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for md_path in sorted(SKILLS_DIR.glob("*/patterns.md")):
        skill = md_path.parent.name
        content = md_path.read_text(encoding="utf-8")
        for line in content.splitlines():
            if not line.startswith("|"):
                continue
            line_wo_anchor = re.sub(
                r"\s*<!--\s*semantic_anchor:.*?-->\s*$", "", line, flags=re.IGNORECASE
            )
            cols = [_unescape_md_cell(c) for c in _split_md_table_cells(line_wo_anchor)]
            if len(cols) < 5:
                continue
            metric_id = _strip_cell_wrapping(cols[0])
            if not _METRIC_ID_RE.match(metric_id):
                continue
            title = _strip_cell_wrapping(cols[1])
            if not include_all and not _is_legacy_target(
                metric_id, title, include_juliet=include_juliet
            ):
                continue
            anti_text = _md_cell_to_text(cols[2])
            stack = _parse_row_stack(cols)
            rows.append(
                {
                    "id": metric_id,
                    "title": title,
                    "skill": skill,
                    "stack": stack,
                    "anti_pattern": anti_text,
                }
            )
    return rows


def build_marker_index() -> set[str]:
    found: set[str] = set()
    needle_re = re.compile(r"Vulnerable:\s*([A-Za-z0-9][A-Za-z0-9.\-]+)")
    for path in TESTBED.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for m in needle_re.finditer(text):
            found.add(m.group(1).upper())
    return found


def render_file_body(ext: str, metric_id: str, anti_pattern: str) -> str:
    marker = _marker_line(ext, metric_id)
    body = (anti_pattern or "").strip()
    if not body or body == _MISSING:
        body = FALLBACK_BODY.get(ext, "insecure\n")
    else:
        body = body.rstrip() + "\n"
    return f"{marker}\n{body}"


def output_path(family: str, skill: str, metric_id: str, ext: str) -> Path:
    return OUTPUT_ROOT / family / skill / f"{_slug(metric_id)}{ext}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fill testbed with Vulnerable markers from patterns.md."
    )
    parser.add_argument("--dry-run", action="store_true", help="Print counts only; do not write files.")
    parser.add_argument(
        "--only-legacy",
        action="store_true",
        help="Only VUL-CVE, NOV-CWE, and Juliet (skip scanner rules).",
    )
    parser.add_argument(
        "--no-juliet",
        action="store_true",
        help="With --only-legacy: skip Juliet HFT-* rows.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite auto_generated files even when marker exists elsewhere.",
    )
    args = parser.parse_args()

    include_all = not args.only_legacy
    include_juliet = not args.no_juliet
    patterns = iter_patterns(include_all=include_all, include_juliet=include_juliet)
    existing = build_marker_index()

    created = 0
    skipped_has_marker = 0
    skipped_exists = 0
    by_family: dict[str, int] = {}

    for row in patterns:
        mid = row["id"]
        if mid in existing and not args.force:
            skipped_has_marker += 1
            continue

        ext = _infer_extension(row["skill"], row["stack"], row["anti_pattern"])
        family = _family(mid, row["title"])
        out = output_path(family, row["skill"], mid, ext)

        if out.exists() and not args.force:
            skipped_exists += 1
            continue

        if args.dry_run:
            created += 1
            by_family[family] = by_family.get(family, 0) + 1
            continue

        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            render_file_body(ext, mid, row["anti_pattern"]),
            encoding="utf-8",
        )
        existing.add(mid)
        created += 1
        by_family[family] = by_family.get(family, 0) + 1

    summary = {
        "targets_scanned": len(patterns),
        "files_created": created,
        "skipped_marker_present": skipped_has_marker,
        "skipped_file_exists": skipped_exists,
        "created_by_family": by_family,
        "output_root": str(OUTPUT_ROOT.relative_to(ROOT)).replace("\\", "/"),
        "include_all": include_all,
        "dry_run": args.dry_run,
    }
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
