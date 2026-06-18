#!/usr/bin/env python3
"""
ETL: import OWASP Benchmark ground-truth pairs into HexVibe ``core/skills/*/patterns.md``.

Reads ``expectedresults*.csv`` from OWASP-Benchmark/BenchmarkJava and BenchmarkPython,
matches one TP + one FP test per CWE, extracts handler code, deduplicates, appends rows,
then runs ``sync_semgrep.py`` and ``render_skill_indexes.py``.

Usage (repo root):
  python scripts/ingest_owasp_benchmark.py
  python scripts/ingest_owasp_benchmark.py --java-repo /path/to/BenchmarkJava --dry-run
"""
from __future__ import annotations

import argparse
import csv
import io
import logging
import re
import shutil
import subprocess
import sys
import textwrap
import zipfile
from collections import defaultdict
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
from typing import Iterable
from urllib.error import URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
SKILLS_DIR = ROOT / "core" / "skills"
CACHE_DIR = ROOT / ".cache" / "owasp-benchmark"

JAVA_REPO_URL = "https://github.com/OWASP-Benchmark/BenchmarkJava.git"
PYTHON_REPO_URL = "https://github.com/OWASP-Benchmark/BenchmarkPython.git"
JAVA_ZIP_URL = "https://github.com/OWASP-Benchmark/BenchmarkJava/archive/refs/heads/master.zip"
PYTHON_ZIP_URL = "https://github.com/OWASP-Benchmark/BenchmarkPython/archive/refs/heads/main.zip"

METRIC_ID_RE = re.compile(r"^[A-Z0-9]{2,8}-[0-9A-Za-z][0-9A-Za-z.\-]*$")
CWE_RE = re.compile(r"CWE-(\d+)", re.I)
BENCHMARK_SOURCE_RE = re.compile(r"OWASP\s+Benchmark\s+(BenchmarkTest\d+)", re.I)
TEST_NAME_RE = re.compile(r"^BenchmarkTest\d+$")

DEFAULT_EXPLOIT = (
    "Атакующий доставляет входные данные, соответствующие anti-pattern; "
    "реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия."
)
DEFAULT_FIX = (
    "Autofix: apply strict allowlist validation, parameterized APIs, "
    "and safe framework defaults per OWASP Benchmark remediation."
)

MAX_CODE_LINES = 10
SIMILARITY_THRESHOLD = 0.72

CATEGORY_TITLES: dict[str, str] = {
    "sqli": "SQL Injection",
    "cmdi": "Command Injection",
    "pathtraver": "Path Traversal",
    "xss": "Cross-Site Scripting (XSS)",
    "ldapi": "LDAP Injection",
    "crypto": "Weak Cryptography",
    "hash": "Weak Hash",
    "weakrand": "Weak Randomness",
    "trustbound": "Trust Boundary Violation",
    "securecookie": "Insecure Cookie",
    "xpathi": "XPath Injection",
    "xxe": "XML External Entity (XXE)",
    "deserial": "Unsafe Deserialization",
    "redirect": "Open Redirect",
    "ssrf": "Server-Side Request Forgery",
    "logforge": "Log Forging",
    "headerinj": "Header Injection",
    "weakalgo": "Weak Algorithm",
    "weakcipher": "Weak Cipher",
}

JAVA_BOILERPLATE = re.compile(
    r"^(package |import |@WebServlet|private static final|serialVersionUID|"
    r"public class |@Override|// some code|response\.setContentType|\}\s*$|\{\s*$)",
    re.I,
)
PYTHON_BOILERPLATE = re.compile(
    r"^(from |import |def init\(|@app\.route|return BenchmarkTest|"
    r"RESPONSE\s*=\s*[\"']{2}|'\"\"\"|\"\"\"|\s*#)",
)


@dataclass(frozen=True)
class BenchmarkRow:
    test_name: str
    category: str
    is_vulnerable: bool
    cwe: int


@dataclass(frozen=True)
class CwePair:
    cwe: int
    category: str
    tp_test: str
    fp_test: str


@dataclass
class SkillTarget:
    lang: str
    skill_dir: str
    id_prefix: str
    stack: str
    test_subpath: str  # format with {test}


log = logging.getLogger("ingest_owasp_benchmark")

TARGETS: dict[str, SkillTarget] = {
    "java": SkillTarget(
        lang="java",
        skill_dir="java-spring",
        id_prefix="JAVA",
        stack="Java/Spring",
        test_subpath="src/main/java/org/owasp/benchmark/testcode/{test}.java",
    ),
    "python": SkillTarget(
        lang="python",
        skill_dir="fastapi-async",
        id_prefix="FAS",
        stack="Python/FastAPI",
        test_subpath="testcode/{test}.py",
    ),
}


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )


def run_cmd(cmd: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    log.debug("exec: %s", " ".join(cmd))
    return subprocess.run(
        cmd,
        cwd=cwd or ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def git_available() -> bool:
    return shutil.which("git") is not None


def clone_or_update_repo(url: str, dest: Path) -> None:
    if dest.exists() and (dest / ".git").is_dir():
        log.info("Updating existing clone: %s", dest)
        proc = run_cmd(["git", "-C", str(dest), "pull", "--ff-only"])
        if proc.returncode != 0:
            log.warning("git pull failed (%s); using existing tree", proc.stderr.strip())
        return
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if git_available():
        log.info("Cloning %s -> %s", url, dest)
        proc = run_cmd(["git", "clone", "--depth", "1", url, str(dest)])
        if proc.returncode == 0:
            return
        log.warning("git clone failed: %s", proc.stderr.strip())
    log.info("Falling back to ZIP download for %s", url)
    download_zip_repo(url, dest)


def download_zip_repo(git_url: str, dest: Path) -> None:
    zip_url = git_url.replace(".git", "/archive/refs/heads/master.zip")
    if "BenchmarkPython" in git_url:
        zip_url = PYTHON_ZIP_URL
    elif "BenchmarkJava" in git_url:
        zip_url = JAVA_ZIP_URL
    try:
        with urlopen(zip_url, timeout=120) as resp:
            payload = resp.read()
    except URLError as exc:
        raise RuntimeError(f"Unable to download {zip_url}: {exc}") from exc
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        shutil.rmtree(dest)
    with zipfile.ZipFile(io.BytesIO(payload)) as zf:
        top = zf.namelist()[0].split("/")[0]
        extract_root = dest.parent / f"_zip_{dest.name}"
        if extract_root.exists():
            shutil.rmtree(extract_root)
        zf.extractall(extract_root)
        (extract_root / top).rename(dest)
        shutil.rmtree(extract_root, ignore_errors=True)
    log.info("Downloaded and extracted %s", dest)


def resolve_repo(path: Path | None, url: str, cache_name: str) -> Path:
    if path is not None:
        p = path.resolve()
        if not p.is_dir():
            raise FileNotFoundError(f"Local repo path not found: {p}")
        log.info("Using local repo: %s", p)
        return p
    dest = CACHE_DIR / cache_name
    clone_or_update_repo(url, dest)
    return dest


def find_expectedresults_csv(repo: Path) -> Path:
    candidates = sorted(
        repo.glob("expectedresults*.csv"),
        key=lambda p: (("1.2" not in p.name, "0.1" not in p.name, p.name)),
    )
    preferred = [
        repo / "expectedresults-1.2.csv",
        repo / "expectedresults-0.1.csv",
        repo / "expectedresults.csv",
    ]
    for p in preferred + candidates:
        if p.is_file():
            log.info("Ground truth CSV: %s", p)
            return p
    raise FileNotFoundError(f"No expectedresults CSV in {repo}")


def parse_expectedresults(csv_path: Path) -> list[BenchmarkRow]:
    rows: list[BenchmarkRow] = []
    text = csv_path.read_text(encoding="utf-8", errors="replace")
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            parts = next(csv.reader([line]))
        except csv.Error:
            continue
        if len(parts) < 4:
            continue
        name, category, vuln_raw, cwe_raw = parts[0], parts[1], parts[2], parts[3]
        if not TEST_NAME_RE.match(name):
            continue
        try:
            cwe = int(cwe_raw.strip())
        except ValueError:
            continue
        is_vuln = vuln_raw.strip().lower() == "true"
        rows.append(
            BenchmarkRow(
                test_name=name,
                category=category.strip().lower(),
                is_vulnerable=is_vuln,
                cwe=cwe,
            )
        )
    log.info("Parsed %d benchmark rows from %s", len(rows), csv_path.name)
    return rows


def build_cwe_pairs(rows: Iterable[BenchmarkRow]) -> list[CwePair]:
    buckets: dict[int, dict[str, list[BenchmarkRow]]] = defaultdict(
        lambda: {"tp": [], "fp": []}
    )
    category_by_cwe: dict[int, str] = {}
    for row in rows:
        key = "tp" if row.is_vulnerable else "fp"
        buckets[row.cwe][key].append(row)
        category_by_cwe.setdefault(row.cwe, row.category)
    pairs: list[CwePair] = []
    for cwe in sorted(buckets):
        tp_list = buckets[cwe]["tp"]
        fp_list = buckets[cwe]["fp"]
        if not tp_list or not fp_list:
            log.debug("CWE-%d: skip (tp=%d fp=%d)", cwe, len(tp_list), len(fp_list))
            continue
        pairs.append(
            CwePair(
                cwe=cwe,
                category=category_by_cwe[cwe],
                tp_test=tp_list[0].test_name,
                fp_test=fp_list[0].test_name,
            )
        )
    log.info("Built %d CWE pairs (TP+FP)", len(pairs))
    return pairs


def _extract_braced_body(source: str, start_idx: int) -> str:
    depth = 0
    i = start_idx
    while i < len(source):
        ch = source[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[start_idx + 1 : i]
        i += 1
    return ""


def extract_java_handler(source: str) -> list[str]:
    for method in ("doPost", "doGet"):
        m = re.search(rf"void\s+{method}\s*\([^)]*\)\s*throws[^{{]*\{{", source)
        if not m:
            m = re.search(rf"void\s+{method}\s*\([^)]*\)\s*\{{", source)
        if m:
            body = _extract_braced_body(source, m.end() - 1)
            return _clean_code_lines(body.splitlines(), JAVA_BOILERPLATE)
    m = re.search(r"public\s+void\s+\w+\s*\([^)]*HttpServletRequest[^)]*\)\s*throws[^{{]*\{{", source)
    if m:
        body = _extract_braced_body(source, m.end() - 1)
        return _clean_code_lines(body.splitlines(), JAVA_BOILERPLATE)
    return _clean_code_lines(source.splitlines(), JAVA_BOILERPLATE)


def extract_python_handler(source: str, test_name: str) -> list[str]:
    for suffix in ("_post", "_get"):
        pat = rf"def\s+{re.escape(test_name)}{suffix}\s*\([^)]*\)\s*:"
        m = re.search(pat, source)
        if not m:
            continue
        start = m.end()
        lines = source[start:].splitlines()
        body_lines: list[str] = []
        for line in lines:
            if line.strip() and not line.startswith((" ", "\t")) and body_lines:
                break
            body_lines.append(line)
        cleaned = _clean_code_lines(body_lines, PYTHON_BOILERPLATE)
        if cleaned:
            return cleaned
    return _clean_code_lines(source.splitlines(), PYTHON_BOILERPLATE)


def _clean_code_lines(lines: Iterable[str], skip_re: re.Pattern[str]) -> list[str]:
    out: list[str] = []
    for raw in lines:
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        if skip_re.match(stripped):
            continue
        if stripped in ("{", "}"):
            continue
        out.append(line.strip())
    if len(out) > MAX_CODE_LINES:
        head = out[: max(3, MAX_CODE_LINES - 2)]
        tail = out[-2:]
        out = head + ["..."] + tail
    return out[:MAX_CODE_LINES]


def read_test_snippet(repo: Path, target: SkillTarget, test_name: str) -> list[str]:
    rel = target.test_subpath.format(test=test_name)
    path = repo / rel
    if not path.is_file():
        log.warning("Test file missing: %s", path)
        return []
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log.warning("Cannot read %s: %s", path, exc)
        return []
    if target.lang == "java":
        return extract_java_handler(source)
    return extract_python_handler(source, test_name)


def lines_to_md_cell(lines: list[str]) -> str:
    if not lines:
        return "`N/A`"
    escaped = [ln.replace("|", "\\|").replace("`", "'") for ln in lines]
    return "<br>".join(f"`{ln}`" for ln in escaped)


def lines_to_fix_template(lines: list[str]) -> str:
    if not lines:
        return DEFAULT_FIX
    flat = " ".join(lines).replace("|", "\\|")
    if len(flat) > 400:
        flat = flat[:397] + "..."
    return flat


def normalize_fingerprint(text: str) -> set[str]:
    tokens = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]{2,}", text.lower())
    return {t for t in tokens if t not in {"string", "request", "response", "param", "true", "false"}}


def similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()


@dataclass
class ExistingPatternIndex:
    cwes: set[str]
    benchmark_tests: set[str]
    anti_fingerprints: list[tuple[str, set[str]]]
    max_numeric_id: int


def split_md_cells(line: str) -> list[str]:
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    return [p.strip() for p in re.split(r"(?<!\\)\|", s)]


def load_existing_index(patterns_path: Path, id_prefix: str) -> ExistingPatternIndex:
    cwes: set[str] = set()
    tests: set[str] = set()
    fps: list[tuple[str, set[str]]] = []
    max_id = 0
    if not patterns_path.is_file():
        return ExistingPatternIndex(cwes, tests, fps, max_id)
    for raw in patterns_path.read_text(encoding="utf-8").splitlines():
        if not raw.strip().startswith("|"):
            continue
        line = re.sub(r"\s*<!--.*?-->\s*$", "", raw, flags=re.I)
        cols = split_md_cells(line)
        if len(cols) < 5:
            continue
        mid = cols[0].strip("` ")
        if not METRIC_ID_RE.match(mid):
            continue
        source_idx = 5 if len(cols) >= 6 else 4
        source = cols[source_idx] if source_idx < len(cols) else ""
        cwes.update(f"CWE-{m}" for m in CWE_RE.findall(source))
        bm = BENCHMARK_SOURCE_RE.search(source)
        if bm:
            tests.add(bm.group(1))
        anti = cols[2] if len(cols) > 2 else ""
        anti_plain = re.sub(r"<br>", "\n", anti)
        anti_plain = re.sub(r"`+", "", anti_plain)
        fps.append((mid, normalize_fingerprint(anti_plain)))
        m = re.match(rf"{re.escape(id_prefix)}-(\d+)", mid, re.I)
        if m:
            max_id = max(max_id, int(m.group(1)))
    return ExistingPatternIndex(cwes, tests, fps, max_id)


def is_duplicate(
    idx: ExistingPatternIndex,
    cwe: int,
    tp_test: str,
    anti_lines: list[str],
) -> tuple[bool, str]:
    cwe_token = f"CWE-{cwe}"
    if cwe_token in idx.cwes:
        return True, f"CWE-{cwe} already in patterns.md"
    if tp_test in idx.benchmark_tests:
        return True, f"benchmark test {tp_test} already imported"
    anti_fp = normalize_fingerprint("\n".join(anti_lines))
    anti_joined = "\n".join(anti_lines)
    for _mid, existing_fp in idx.anti_fingerprints:
        if not anti_fp or not existing_fp:
            continue
        inter = len(anti_fp & existing_fp)
        union = len(anti_fp | existing_fp)
        jaccard = inter / union if union else 0.0
        if jaccard >= SIMILARITY_THRESHOLD:
            return True, f"similar anti-pattern (jaccard={jaccard:.2f})"
        if similarity(anti_joined, " ".join(sorted(existing_fp))) >= SIMILARITY_THRESHOLD:
            return True, "similar anti-pattern (sequence ratio)"
    return False, ""


def title_for_pair(target: SkillTarget, pair: CwePair) -> str:
    cat_title = CATEGORY_TITLES.get(pair.category, pair.category)
    lang_label = "Java" if target.lang == "java" else "Python"
    return f"OWASP Benchmark {lang_label}: {cat_title} (CWE-{pair.cwe})"


def build_semantic_anchor(metric_id: str, title: str, anti_lines: list[str]) -> str:
    blob = " ".join([metric_id.lower(), title.lower(), " ".join(anti_lines[:6]).lower()])
    tokens = re.findall(r"[a-z0-9]{2,}", blob.replace("_", " "))
    seen: set[str] = set()
    ordered: list[str] = []
    for t in tokens:
        if t in seen:
            continue
        seen.add(t)
        ordered.append(t)
        if len(ordered) >= 24:
            break
    return f"<!-- semantic_anchor: {' '.join(ordered)} -->"


def format_table_row(
    metric_id: str,
    title: str,
    anti_cell: str,
    safe_cell: str,
    stack: str,
    source: str,
    fix_template: str,
    exploit: str,
    anchor: str,
) -> str:
    title_esc = title.replace("|", "\\|")
    exploit_esc = exploit.replace("|", "\\|")
    fix_esc = fix_template.replace("|", "\\|")
    return (
        f"| {metric_id} | {title_esc} | {anti_cell} | {safe_cell} | {stack} | "
        f"`{source}` | `{fix_esc}` | {exploit_esc} | {anchor} |"
    )


def ensure_table_header(patterns_path: Path) -> None:
    if patterns_path.is_file() and patterns_path.read_text(encoding="utf-8").strip():
        return
    patterns_path.parent.mkdir(parents=True, exist_ok=True)
    header = (
        "| ID | Название метрики | Anti-Pattern (Vulnerable Code/YAML) | "
        "Safe-Pattern (Remediation) | Stack | Источник  fix_template | Exploit scenario |\n"
        "|---|---|---|---|---|---|---|\n"
    )
    patterns_path.write_text(header, encoding="utf-8")


def append_pattern_row(patterns_path: Path, row_line: str) -> None:
    ensure_table_header(patterns_path)
    text = patterns_path.read_text(encoding="utf-8")
    if not text.endswith("\n"):
        text += "\n"
    patterns_path.write_text(text + row_line + "\n", encoding="utf-8")


def process_benchmark(
    repo: Path,
    target: SkillTarget,
    *,
    dry_run: bool,
) -> tuple[int, int, int]:
    csv_path = find_expectedresults_csv(repo)
    rows = parse_expectedresults(csv_path)
    pairs = build_cwe_pairs(rows)
    patterns_path = SKILLS_DIR / target.skill_dir / "patterns.md"
    idx = load_existing_index(patterns_path, target.id_prefix)
    next_id = idx.max_numeric_id + 1

    imported = skipped = failed = 0
    log.info("=== Processing %s (%s) ===", target.lang, patterns_path)

    for pair in pairs:
        cwe_label = f"CWE-{pair.cwe}"
        anti_lines = read_test_snippet(repo, target, pair.tp_test)
        safe_lines = read_test_snippet(repo, target, pair.fp_test)
        if not anti_lines:
            log.warning("SKIP %s: empty anti-pattern extraction (%s)", cwe_label, pair.tp_test)
            failed += 1
            continue
        if not safe_lines:
            log.warning("SKIP %s: empty safe-pattern extraction (%s)", cwe_label, pair.fp_test)
            failed += 1
            continue

        dup, reason = is_duplicate(idx, pair.cwe, pair.tp_test, anti_lines)
        if dup:
            log.info("SKIP %s (%s/%s): duplicate — %s", cwe_label, pair.tp_test, pair.fp_test, reason)
            skipped += 1
            continue

        metric_id = f"{target.id_prefix}-{next_id:03d}"
        next_id += 1
        title = title_for_pair(target, pair)
        source = f"OWASP Benchmark {pair.tp_test}"
        anti_cell = lines_to_md_cell(anti_lines)
        safe_cell = lines_to_md_cell(safe_lines)
        fix_template = lines_to_fix_template(safe_lines)
        anchor = build_semantic_anchor(metric_id, title, anti_lines)
        row = format_table_row(
            metric_id,
            title,
            anti_cell,
            safe_cell,
            target.stack,
            source,
            fix_template,
            DEFAULT_EXPLOIT,
            anchor,
        )

        if dry_run:
            log.info(
                "DRY-RUN import %s -> %s [%s] TP=%s FP=%s",
                cwe_label,
                metric_id,
                target.skill_dir,
                pair.tp_test,
                pair.fp_test,
            )
        else:
            append_pattern_row(patterns_path, row)
            idx.cwes.add(cwe_label)
            idx.benchmark_tests.add(pair.tp_test)
            idx.anti_fingerprints.append((metric_id, normalize_fingerprint("\n".join(anti_lines))))
            log.info(
                "IMPORTED %s -> %s (%s) TP=%s FP=%s",
                cwe_label,
                metric_id,
                target.skill_dir,
                pair.tp_test,
                pair.fp_test,
            )
        imported += 1

    log.info(
        "%s summary: imported=%d skipped=%d failed=%d",
        target.lang,
        imported,
        skipped,
        failed,
    )
    return imported, skipped, failed


def run_post_pipeline(skip_sync: bool) -> None:
    if skip_sync:
        log.info("Skipping post-pipeline (--skip-sync)")
        return
    for script in ("scripts/sync_semgrep.py", "scripts/render_skill_indexes.py"):
        log.info("Running %s ...", script)
        proc = run_cmd([sys.executable, script])
        if proc.stdout.strip():
            log.debug(proc.stdout.strip())
        if proc.returncode != 0:
            log.error("%s failed (exit %s):\n%s", script, proc.returncode, proc.stderr.strip())
            raise RuntimeError(f"Post-pipeline script failed: {script}")
        log.info("%s completed OK", script)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Import OWASP Benchmark CWE pairs into HexVibe patterns.md",
    )
    p.add_argument(
        "--java-repo",
        type=Path,
        default=None,
        help="Local path to BenchmarkJava (skip clone)",
    )
    p.add_argument(
        "--python-repo",
        type=Path,
        default=None,
        help="Local path to BenchmarkPython (skip clone)",
    )
    p.add_argument(
        "--cache-dir",
        type=Path,
        default=CACHE_DIR,
        help="Clone cache directory (default: .cache/owasp-benchmark)",
    )
    p.add_argument(
        "--lang",
        choices=("java", "python", "all"),
        default="all",
        help="Which benchmark to ingest (default: all)",
    )
    p.add_argument("--dry-run", action="store_true", help="Parse and log only; do not write files")
    p.add_argument("--skip-sync", action="store_true", help="Do not run sync_semgrep / render_skill_indexes")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logging(args.verbose)
    global CACHE_DIR
    CACHE_DIR = args.cache_dir.resolve()

    log.info("HexVibe OWASP Benchmark ingest (root=%s)", ROOT)
    total_imported = 0
    any_write = False

    try:
        if args.lang in ("java", "all"):
            java_repo = resolve_repo(args.java_repo, JAVA_REPO_URL, "BenchmarkJava")
            imp, skip, fail = process_benchmark(java_repo, TARGETS["java"], dry_run=args.dry_run)
            total_imported += imp
            any_write = any_write or (imp > 0 and not args.dry_run)

        if args.lang in ("python", "all"):
            python_repo = resolve_repo(args.python_repo, PYTHON_REPO_URL, "BenchmarkPython")
            imp, skip, fail = process_benchmark(python_repo, TARGETS["python"], dry_run=args.dry_run)
            total_imported += imp
            any_write = any_write or (imp > 0 and not args.dry_run)

        if any_write:
            run_post_pipeline(args.skip_sync)
        elif total_imported == 0:
            log.info("No new patterns imported; post-pipeline not invoked")
        else:
            log.info("Dry-run complete; no files modified")

        log.info("Done. Total new patterns: %d", total_imported)
        return 0
    except Exception:
        log.exception("Ingest failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
