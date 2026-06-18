#!/usr/bin/env python3
"""
ETL: import CryptoAPI-Bench, Juliet C/C++, and Nuclei templates into HexVibe ``core/skills/*/patterns.md``.

Strategy pattern: ``BaseExtractor`` + ``CryptoApiExtractor``, ``JulietExtractor``, ``NucleiExtractor``.

Usage (repo root):
  python scripts/ingest_advanced_datasets.py --target all
  python scripts/ingest_advanced_datasets.py --target juliet --dry-run --limit 10
  python scripts/ingest_advanced_datasets.py --target nuclei --nuclei-repo /path/to/nuclei-templates
"""
from __future__ import annotations

import argparse
import io
import logging
import re
import shutil
import subprocess
import sys
import zipfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Iterable, Iterator
from urllib.error import URLError
from urllib.request import urlopen

try:
    import yaml  # type: ignore
except ImportError:
    yaml = None  # type: ignore[assignment]

ROOT = Path(__file__).resolve().parents[1]
SKILLS_DIR = ROOT / "core" / "skills"
CACHE_DIR = ROOT / ".cache" / "advanced-datasets"

CRYPTO_REPO_URL = "https://github.com/CryptoAPI-Bench/CryptoAPI-Bench.git"
CRYPTO_ZIP_URL = "https://github.com/CryptoAPI-Bench/CryptoAPI-Bench/archive/refs/heads/master.zip"

JULIET_REPO_URL = "https://github.com/arichardson/juliet-test-suite-c.git"
JULIET_ZIP_URL = "https://github.com/arichardson/juliet-test-suite-c/archive/refs/heads/master.zip"

NUCLEI_REPO_URL = "https://github.com/projectdiscovery/nuclei-templates.git"
NUCLEI_ZIP_URL = "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip"

METRIC_ID_RE = re.compile(r"^[A-Z0-9]{2,8}-[0-9A-Za-z][0-9A-Za-z.\-]*$")
CWE_RE = re.compile(r"CWE[_-]?(\d+)", re.I)
CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.I)

BB_CASE_RE = re.compile(r"BBCase", re.I)

OMITBAD_RE = re.compile(
    r"#ifndef\s+OMITBAD\b(.*?)(?=#endif\s*/\*\s*OMITBAD\s*\*/)",
    re.DOTALL | re.IGNORECASE,
)
OMITGOOD_RE = re.compile(
    r"#ifndef\s+OMITGOOD\b(.*?)(?=#endif\s*/\*\s*OMITGOOD\s*\*/)",
    re.DOTALL | re.IGNORECASE,
)
GOOD_B2G_RE = re.compile(
    r"(static\s+)?void\s+goodB2G\s*\([^)]*\)\s*\{.*?\n\}",
    re.DOTALL,
)

RAW_HTTP_RE = re.compile(
    r"^\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE)\s+(\S+)\s+HTTP/",
    re.MULTILINE | re.IGNORECASE,
)

JAVA_GO_METHOD_RE = re.compile(
    r"(?:public|private|protected)?\s+(?:static\s+)?[\w<>,\[\]\s]+\s+go\s*\([^)]*\)\s*(?:throws[^{]*)?\{",
    re.DOTALL | re.IGNORECASE,
)
JAVA_MAIN_METHOD_RE = re.compile(
    r"(?:public|private|protected)?\s+static\s+void\s+main\s*\([^)]*\)\s*(?:throws[^{]*)?\{",
    re.DOTALL | re.IGNORECASE,
)

JAVA_BOILERPLATE = re.compile(
    r"^(package |import |public class |@Override|//|\}\s*$|\{\s*$)",
    re.I,
)
C_BOILERPLATE = re.compile(
    r"^(#include|#pragma|/\*|#ifdef|#ifndef|#else|#endif|\}\s*$|\{\s*$)",
)

DEFAULT_EXPLOIT = (
    "Атакующий доставляет входные данные, соответствующие anti-pattern; "
    "реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия."
)
NUCLEI_SAFE_PLACEHOLDER = "TODO: AI Generate mitigation"
DEFAULT_FIX = (
    "Autofix: apply dataset-recommended remediation, secure defaults, "
    "and framework guardrails."
)

MAX_CODE_LINES = 12
SIMILARITY_THRESHOLD = 0.72
HIGH_SEVERITIES = frozenset({"high", "critical"})

log = logging.getLogger("ingest_advanced_datasets")


@dataclass(frozen=True)
class DomainTarget:
    skill_dir: str
    id_prefix: str
    stack: str


CRYPTO_TARGET = DomainTarget("java-spring", "JAVA", "Java")
JULIET_TARGET = DomainTarget("hft-cpp-security", "HFT", "C/C++")
NUCLEI_TARGET = DomainTarget("integration-security", "ITS", "Network/API")


@dataclass
class DatasetPattern:
    check_id: str
    title: str
    anti_lines: list[str]
    safe_lines: list[str]
    target: DomainTarget
    source: str
    dataset: str


@dataclass
class PatternIndex:
    known_ids: set[str] = field(default_factory=set)
    source_tokens: set[str] = field(default_factory=set)
    imported_check_ids: set[str] = field(default_factory=set)
    anti_fingerprints: list[tuple[str, set[str]]] = field(default_factory=list)
    max_ids: dict[str, int] = field(default_factory=dict)


SOURCE_CHECK_ID_RE = re.compile(
    r"(?:Juliet|CryptoAPI-Bench|Nuclei)\s+([A-Za-z0-9][A-Za-z0-9_\-]*)",
    re.I,
)
MAX_SIMILARITY_FINGERPRINTS = 200


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


def clone_or_update_repo(url: str, dest: Path, zip_url: str) -> None:
    if dest.exists() and (dest / ".git").is_dir():
        log.info("Updating clone: %s", dest)
        proc = run_cmd(["git", "-C", str(dest), "pull", "--ff-only"])
        if proc.returncode != 0:
            log.warning("git pull failed; using existing tree: %s", proc.stderr.strip())
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
    log.info("ZIP fallback for %s", url)
    download_zip_repo(zip_url, dest)


def download_zip_repo(zip_url: str, dest: Path) -> None:
    try:
        with urlopen(zip_url, timeout=180) as resp:
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


def resolve_repo(path: Path | None, url: str, cache_name: str, zip_url: str) -> Path:
    if path is not None:
        p = path.resolve()
        if not p.is_dir():
            raise FileNotFoundError(f"Local repo not found: {p}")
        log.info("Using local repo: %s", p)
        return p
    dest = CACHE_DIR / cache_name
    clone_or_update_repo(url, dest, zip_url)
    return dest


def split_md_cells(line: str) -> list[str]:
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    return [p.strip() for p in re.split(r"(?<!\\)\|", s)]


def normalize_fingerprint(text: str) -> set[str]:
    tokens = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]{2,}", text.lower())
    skip = {
        "string", "request", "response", "param", "true", "false", "void", "int",
        "public", "static", "class", "include", "define",
    }
    return {t for t in tokens if t not in skip}


def similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()


def load_pattern_index(patterns_path: Path, id_prefix: str) -> PatternIndex:
    idx = PatternIndex()
    if not patterns_path.is_file():
        return idx
    fingerprint_rows: list[tuple[str, str]] = []
    for raw in patterns_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not raw.strip().startswith("|"):
            continue
        line = re.sub(r"\s*<!--.*?-->\s*$", "", raw, flags=re.I)
        cols = split_md_cells(line)
        if len(cols) < 5:
            continue
        mid = cols[0].strip("` ")
        if not METRIC_ID_RE.match(mid):
            continue
        idx.known_ids.add(mid.upper())
        source_idx = 5 if len(cols) >= 6 else 4
        source = cols[source_idx] if source_idx < len(cols) else ""
        for token in re.findall(r"[A-Za-z0-9][A-Za-z0-9_\-./]{2,}", source):
            idx.source_tokens.add(token.upper())
        src_m = SOURCE_CHECK_ID_RE.search(source.strip("` "))
        if src_m:
            idx.imported_check_ids.add(src_m.group(1).upper())
        anti = cols[2] if len(cols) > 2 else ""
        fingerprint_rows.append((mid, anti))
        m = re.match(rf"{re.escape(id_prefix)}-(\d+)", mid, re.I)
        if m:
            idx.max_ids[id_prefix] = max(idx.max_ids.get(id_prefix, 0), int(m.group(1)))
    for mid, anti in fingerprint_rows[-MAX_SIMILARITY_FINGERPRINTS:]:
        anti_plain = re.sub(r"<br>", "\n", anti)
        anti_plain = re.sub(r"`+", "", anti_plain)
        idx.anti_fingerprints.append((mid, normalize_fingerprint(anti_plain)))
    return idx


def is_duplicate(idx: PatternIndex, check_id: str, anti_lines: list[str]) -> tuple[bool, str]:
    cid = check_id.upper()
    if cid in idx.imported_check_ids or cid in idx.source_tokens or cid in idx.known_ids:
        return True, f"id/token {check_id} already present"
    anti_fp = normalize_fingerprint("\n".join(anti_lines))
    anti_joined = "\n".join(anti_lines)
    recent = idx.anti_fingerprints[-MAX_SIMILARITY_FINGERPRINTS:]
    for _mid, existing in recent:
        if not anti_fp or not existing:
            continue
        inter = len(anti_fp & existing)
        union = len(anti_fp | existing)
        jaccard = inter / union if union else 0.0
        if jaccard >= SIMILARITY_THRESHOLD:
            return True, f"similar anti-pattern (jaccard={jaccard:.2f})"
        if similarity(anti_joined, " ".join(sorted(existing))) >= SIMILARITY_THRESHOLD:
            return True, "similar anti-pattern (sequence ratio)"
    return False, ""


def trim_lines(lines: list[str], limit: int = MAX_CODE_LINES) -> list[str]:
    cleaned = [ln.rstrip() for ln in lines if ln.strip()]
    if len(cleaned) <= limit:
        return cleaned
    head = cleaned[: max(3, limit - 2)]
    tail = cleaned[-2:]
    return head + ["..."] + tail


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
    return trim_lines(out)


def extract_java_method_body(source: str) -> list[str]:
    for pattern in (JAVA_GO_METHOD_RE, JAVA_MAIN_METHOD_RE):
        m = pattern.search(source)
        if m:
            body = _extract_braced_body(source, m.end() - 1)
            cleaned = _clean_code_lines(body.splitlines(), JAVA_BOILERPLATE)
            if cleaned:
                return cleaned
    return _clean_code_lines(source.splitlines(), JAVA_BOILERPLATE)


def extract_c_code_block(block: str) -> list[str]:
    if not block.strip():
        return []
    lines = block.splitlines()
    # Prefer goodB2G when present inside OMITGOOD (bad source + good sink).
    b2g = GOOD_B2G_RE.search(block)
    if b2g:
        fn_body = _extract_braced_body(b2g.group(0), b2g.group(0).index("{"))
        cleaned = _clean_code_lines(fn_body.splitlines(), C_BOILERPLATE)
        if cleaned:
            return cleaned
    bad_fn = re.search(r"void\s+\w+_bad\s*\([^)]*\)\s*\{", block)
    if bad_fn:
        body = _extract_braced_body(block, bad_fn.end() - 1)
        cleaned = _clean_code_lines(body.splitlines(), C_BOILERPLATE)
        if cleaned:
            return cleaned
    return _clean_code_lines(lines, C_BOILERPLATE)


def extract_juliet_omit_block(source: str, macro: str) -> str:
    """Extract preprocessor block with re.DOTALL; fallback scans to annotated #endif."""
    primary = OMITBAD_RE if macro.upper() == "OMITBAD" else OMITGOOD_RE
    m = primary.search(source)
    if m:
        return m.group(1).strip()
    start = re.search(rf"#ifndef\s+{macro}\b", source, re.I)
    if not start:
        return ""
    pos = start.end()
    annotated = re.search(rf"#endif\s*/\*\s*{macro}\s*\*/", source[pos:], re.I)
    if annotated:
        return source[pos : pos + annotated.start()].strip()
    # Generic fallback: first #endif after block start (no nested OMIT* macros expected).
    generic = re.search(r"#endif\b", source[pos:])
    if generic:
        return source[pos : pos + generic.start()].strip()
    return ""


def extract_cwe_from_path(path: Path) -> str | None:
    for part in path.parts:
        m = re.match(r"CWE(\d+)", part, re.I)
        if m:
            return f"CWE-{m.group(1)}"
    m = CWE_RE.search(path.stem)
    if m:
        return f"CWE-{m.group(1)}"
    return None


def humanize_cwe_dir(dirname: str) -> str:
    m = re.match(r"CWE(\d+)_(.+)", dirname, re.I)
    if not m:
        return dirname.replace("_", " ")
    return f"CWE-{m.group(1)} {m.group(2).replace('_', ' ')}"


def lines_to_md_cell(lines: list[str]) -> str:
    if not lines:
        return "`N/A`"
    escaped = [ln.replace("|", "\\|").replace("`", "'") for ln in lines]
    return "<br>".join(f"`{ln}`" for ln in escaped)


def lines_to_fix_template(lines: list[str]) -> str:
    if not lines:
        return DEFAULT_FIX
    flat = " ".join(lines).replace("|", "\\|")
    return flat[:400] + ("..." if len(flat) > 400 else "")


def build_semantic_anchor(metric_id: str, title: str, anti_lines: list[str]) -> str:
    blob = " ".join([metric_id.lower(), title.lower(), " ".join(anti_lines[:6]).lower()])
    tokens: list[str] = []
    seen: set[str] = set()
    for t in re.findall(r"[a-z0-9]{2,}", blob.replace("_", " ")):
        if t in seen:
            continue
        seen.add(t)
        tokens.append(t)
        if len(tokens) >= 24:
            break
    return f"<!-- semantic_anchor: {' '.join(tokens)} -->"


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
    if patterns_path.is_file() and patterns_path.read_text(encoding="utf-8", errors="replace").strip():
        return
    patterns_path.parent.mkdir(parents=True, exist_ok=True)
    header = (
        "| ID | Название метрики | Anti-Pattern (Vulnerable Code/YAML) | "
        "Safe-Pattern (Remediation) | Stack | Источник  fix_template | Exploit scenario |\n"
        "|---|---|---|---|---|---|---|\n"
    )
    patterns_path.write_text(header, encoding="utf-8")


def sanitize_text_for_write(text: str) -> str:
    cleaned = text.replace("\x00", "")
    return cleaned.encode("utf-8", errors="surrogatepass").decode("utf-8", errors="replace")


def append_pattern_rows(patterns_path: Path, row_lines: list[str]) -> None:
    if not row_lines:
        return
    ensure_table_header(patterns_path)
    text = patterns_path.read_text(encoding="utf-8", errors="replace")
    if not text.endswith("\n"):
        text += "\n"
    payload = sanitize_text_for_write(text + "\n".join(row_lines) + "\n")
    patterns_path.write_text(payload, encoding="utf-8", errors="replace")


def append_pattern_row(patterns_path: Path, row_line: str) -> None:
    append_pattern_rows(patterns_path, [row_line])


def next_metric_id(idx: PatternIndex, prefix: str) -> str:
    n = idx.max_ids.get(prefix, 0) + 1
    idx.max_ids[prefix] = n
    return f"{prefix}-{n:03d}"


def read_source(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def pair_crypto_secure_file(bb_path: Path) -> Path | None:
    directory = bb_path.parent
    stem = bb_path.stem
    sb_name = BB_CASE_RE.sub("SBCase", stem)
    candidates = [directory / f"{sb_name}.java"]
    for candidate in candidates:
        if candidate.is_file() and candidate != bb_path:
            return candidate
    # Upstream CryptoAPI-Bench ships *Corrected.java instead of *SBCase*.java.
    corrected = sorted(directory.glob("*Corrected.java"))
    if corrected:
        return corrected[0]
    return None


def parse_nuclei_yaml_light(text: str) -> dict[str, Any]:
    """Minimal Nuclei YAML parser when PyYAML is unavailable."""
    doc: dict[str, Any] = {}
    id_m = re.search(r"^id:\s*(\S+)", text, re.M)
    if id_m:
        doc["id"] = id_m.group(1).strip()
    info: dict[str, Any] = {}
    name_m = re.search(r"^\s{2}name:\s*(.+)$", text, re.M)
    if name_m:
        info["name"] = name_m.group(1).strip().strip("'\"")
    sev_m = re.search(r"^\s{2}severity:\s*(\S+)", text, re.M)
    if sev_m:
        info["severity"] = sev_m.group(1).strip().lower()
    if info:
        doc["info"] = info
    raw_blocks = re.findall(r"^\s+-\s*\|\s*\n((?:\s+.+\n?)+)", text, re.M)
    if raw_blocks:
        http_items = [{"raw": block} for block in raw_blocks]
        doc["http"] = http_items
    return doc


def load_nuclei_doc(raw: str) -> dict[str, Any] | None:
    if yaml is not None:
        try:
            doc = yaml.safe_load(raw)
            if isinstance(doc, dict):
                return doc
        except Exception:
            log.debug("PyYAML parse failed; using light parser")
    doc = parse_nuclei_yaml_light(raw)
    return doc if doc else None


def parse_nuclei_severity(doc: dict[str, Any]) -> str:
    info = doc.get("info") or {}
    sev = info.get("severity")
    return str(sev).strip().lower() if sev is not None else ""


def parse_nuclei_title(doc: dict[str, Any]) -> str:
    info = doc.get("info") or {}
    name = info.get("name")
    if name:
        return str(name).strip()
    return str(doc.get("id", "Nuclei template"))


def extract_http_requests_from_block(block: Any) -> list[tuple[str, str]]:
    """Return (METHOD, path) pairs from nuclei http/requests YAML nodes."""
    pairs: list[tuple[str, str]] = []
    if block is None:
        return pairs
    items = block if isinstance(block, list) else [block]
    for item in items:
        if not isinstance(item, dict):
            continue
        method = item.get("method")
        path = item.get("path")
        if method and path:
            pairs.append((str(method).upper(), str(path)))
            continue
        raw = item.get("raw")
        if raw is None:
            continue
        raw_text = raw if isinstance(raw, str) else "\n".join(str(x) for x in raw)
        for m in RAW_HTTP_RE.finditer(raw_text):
            pairs.append((m.group(1).upper(), m.group(2)))
    return pairs


def extract_nuclei_anti_lines(doc: dict[str, Any]) -> list[str]:
    pairs: list[tuple[str, str]] = []
    for key in ("http", "requests"):
        pairs.extend(extract_http_requests_from_block(doc.get(key)))
    if not pairs:
        return []
    # Prefer the last request — often the exploitation step in multi-step flows.
    method, path = pairs[-1]
    return trim_lines([f"{method} {path}"])


def nuclei_template_allowed(path: Path) -> bool:
    posix = path.as_posix().lower()
    return "/cves/" in posix or "/vulnerabilities/" in posix


class BaseExtractor(ABC):
    dataset_name: str = "dataset"

    def __init__(self, repo: Path, *, limit: int | None = None) -> None:
        self.repo = repo
        self.limit = limit
        self._files_seen = 0

    def _take_file(self) -> bool:
        if self.limit is None:
            return True
        if self._files_seen >= self.limit:
            return False
        self._files_seen += 1
        return True

    @abstractmethod
    def extract(self) -> list[DatasetPattern]:
        ...


class CryptoApiExtractor(BaseExtractor):
    dataset_name = "crypto"

    def extract(self) -> list[DatasetPattern]:
        patterns: list[DatasetPattern] = []
        java_root = self.repo
        nested = self.repo / "CryptoAPI-Bench"
        if nested.is_dir():
            java_root = nested
        bb_files = sorted(java_root.rglob("*BBCase*.java"))
        log.info("CryptoAPI-Bench: scanning %d BBCase files under %s", len(bb_files), java_root)
        for bb_path in bb_files:
            if not self._take_file():
                break
            sb_path = pair_crypto_secure_file(bb_path)
            if sb_path is None:
                log.debug("No secure pair for %s", bb_path.name)
                continue
            try:
                bb_src = read_source(bb_path)
                sb_src = read_source(sb_path)
            except OSError as exc:
                log.warning("Cannot read %s: %s", bb_path, exc)
                continue
            anti_lines = extract_java_method_body(bb_src)
            safe_lines = extract_java_method_body(sb_src)
            if not anti_lines:
                log.debug("Empty anti-pattern: %s", bb_path)
                continue
            if not safe_lines:
                log.debug("Empty safe-pattern: %s", sb_path)
                continue
            category = bb_path.parent.name
            case_id = bb_path.stem
            title = f"CryptoAPI-Bench {category}: {case_id}"
            source = f"CryptoAPI-Bench {case_id}"
            patterns.append(
                DatasetPattern(
                    check_id=case_id,
                    title=title,
                    anti_lines=anti_lines,
                    safe_lines=safe_lines,
                    target=CRYPTO_TARGET,
                    source=source,
                    dataset=self.dataset_name,
                )
            )
        log.info("CryptoAPI-Bench extracted %d patterns", len(patterns))
        return patterns


class JulietExtractor(BaseExtractor):
    dataset_name = "juliet"

    def extract(self) -> list[DatasetPattern]:
        patterns: list[DatasetPattern] = []
        testcases = self.repo / "testcases"
        if not testcases.is_dir():
            log.warning("Juliet testcases/ not found in %s", self.repo)
            return patterns
        sources = sorted(list(testcases.rglob("*.c")) + list(testcases.rglob("*.cpp")))
        log.info("Juliet: scanning %d C/C++ files", len(sources))
        for src_path in sources:
            if not self._take_file():
                break
            try:
                source = read_source(src_path)
            except OSError as exc:
                log.warning("Cannot read %s: %s", src_path, exc)
                continue
            bad_block = extract_juliet_omit_block(source, "OMITBAD")
            good_block = extract_juliet_omit_block(source, "OMITGOOD")
            if not bad_block:
                log.debug("No OMITBAD block: %s", src_path.name)
                continue
            anti_lines = extract_c_code_block(bad_block)
            safe_lines = extract_c_code_block(good_block) if good_block else []
            if not anti_lines:
                log.debug("Empty anti extraction: %s", src_path.name)
                continue
            if not safe_lines and good_block:
                safe_lines = trim_lines(good_block.splitlines())
            if not safe_lines:
                log.debug("No OMITGOOD block: %s", src_path.name)
                continue
            cwe = extract_cwe_from_path(src_path) or "CWE-UNKNOWN"
            cwe_dir = next(
                (p.name for p in src_path.parents if p.name.upper().startswith("CWE")),
                src_path.stem,
            )
            title = f"Juliet {humanize_cwe_dir(cwe_dir)}: {src_path.stem}"
            source = f"Juliet {src_path.stem} ({cwe})"
            patterns.append(
                DatasetPattern(
                    check_id=src_path.stem,
                    title=title,
                    anti_lines=anti_lines,
                    safe_lines=safe_lines,
                    target=JULIET_TARGET,
                    source=source,
                    dataset=self.dataset_name,
                )
            )
        log.info("Juliet extracted %d patterns", len(patterns))
        return patterns


class NucleiExtractor(BaseExtractor):
    dataset_name = "nuclei"

    def extract(self) -> list[DatasetPattern]:
        patterns: list[DatasetPattern] = []
        yaml_files = sorted(
            p for p in self.repo.rglob("*.yaml") if nuclei_template_allowed(p)
        )
        log.info("Nuclei: scanning %d yaml files in cves/ and vulnerabilities/", len(yaml_files))
        for ypath in yaml_files:
            if not self._take_file():
                break
            try:
                raw = ypath.read_text(encoding="utf-8", errors="replace")
                doc = load_nuclei_doc(raw)
            except OSError as exc:
                log.debug("Skip %s: %s", ypath, exc)
                continue
            if not doc:
                continue
            severity = parse_nuclei_severity(doc)
            if severity not in HIGH_SEVERITIES:
                continue
            anti_lines = extract_nuclei_anti_lines(doc)
            if not anti_lines:
                log.debug("No HTTP request in %s", ypath.name)
                continue
            template_id = str(doc.get("id") or ypath.stem)
            title = parse_nuclei_title(doc)
            cve = CVE_RE.search(template_id) or CVE_RE.search(ypath.as_posix())
            cve_label = cve.group(0).upper() if cve else template_id
            source = f"Nuclei {template_id}"
            patterns.append(
                DatasetPattern(
                    check_id=template_id,
                    title=f"Nuclei: {title}",
                    anti_lines=anti_lines,
                    safe_lines=[NUCLEI_SAFE_PLACEHOLDER],
                    target=NUCLEI_TARGET,
                    source=source,
                    dataset=self.dataset_name,
                )
            )
        log.info("Nuclei extracted %d high/critical patterns", len(patterns))
        return patterns


EXTRACTORS: dict[str, type[BaseExtractor]] = {
    "crypto": CryptoApiExtractor,
    "juliet": JulietExtractor,
    "nuclei": NucleiExtractor,
}


def write_patterns(items: Iterable[DatasetPattern], *, dry_run: bool) -> int:
    indices: dict[str, PatternIndex] = {}
    pending_rows: dict[Path, list[str]] = {}
    pending_meta: list[tuple[PatternIndex, str, str, list[str]]] = []
    imported = 0
    skipped = 0

    def flush_pending() -> None:
        for path, rows in pending_rows.items():
            try:
                append_pattern_rows(path, rows)
            except OSError as exc:
                log.error("FAILED batch write %s (%d rows): %s", path, len(rows), exc)
                raise
        for idx, metric_id, check_id, anti_lines in pending_meta:
            idx.known_ids.add(metric_id.upper())
            idx.source_tokens.add(check_id.upper())
            idx.imported_check_ids.add(check_id.upper())
            idx.anti_fingerprints.append(
                (metric_id, normalize_fingerprint("\n".join(anti_lines)))
            )
        pending_rows.clear()
        pending_meta.clear()

    for item in items:
        patterns_path = SKILLS_DIR / item.target.skill_dir / "patterns.md"
        prefix = item.target.id_prefix
        if prefix not in indices:
            indices[prefix] = load_pattern_index(patterns_path, prefix)

        idx = indices[prefix]
        dup, reason = is_duplicate(idx, item.check_id, item.anti_lines)
        if dup:
            skipped += 1
            if skipped <= 20 or skipped % 5000 == 0:
                log.info(
                    "SKIP %s -> %s: duplicate — %s",
                    item.check_id,
                    item.target.skill_dir,
                    reason,
                )
            continue

        metric_id = next_metric_id(idx, prefix)
        anti_cell = lines_to_md_cell(item.anti_lines)
        safe_cell = lines_to_md_cell(item.safe_lines)
        fix_template = (
            NUCLEI_SAFE_PLACEHOLDER
            if item.dataset == "nuclei"
            else lines_to_fix_template(item.safe_lines)
        )
        anchor = build_semantic_anchor(metric_id, item.title, item.anti_lines)
        row = format_table_row(
            metric_id,
            item.title,
            anti_cell,
            safe_cell,
            item.target.stack,
            item.source,
            fix_template,
            DEFAULT_EXPLOIT,
            anchor,
        )

        if dry_run:
            if imported < 20 or imported % 5000 == 0:
                log.info(
                    "DRY-RUN import %s -> %s [%s] dataset=%s",
                    item.check_id,
                    metric_id,
                    item.target.skill_dir,
                    item.dataset,
                )
        else:
            pending_rows.setdefault(patterns_path, []).append(row)
            pending_meta.append((idx, metric_id, item.check_id, item.anti_lines))
            if len(pending_meta) >= 1000:
                flush_pending()
            if imported < 20 or imported % 5000 == 0:
                log.info(
                    "IMPORTED %s -> %s (%s) dataset=%s",
                    item.check_id,
                    metric_id,
                    item.target.skill_dir,
                    item.dataset,
                )
        imported += 1

    if not dry_run and pending_meta:
        flush_pending()

    log.info("Write summary: imported=%d skipped=%d", imported, skipped)
    return imported


def run_post_pipeline(skip_sync: bool) -> None:
    if skip_sync:
        log.info("Skipping post-pipeline (--skip-sync)")
        return
    script = "scripts/sync_semgrep.py"
    log.info("Running %s ...", script)
    proc = run_cmd([sys.executable, script])
    if proc.returncode != 0:
        log.error("%s failed:\n%s", script, proc.stderr.strip())
        raise RuntimeError(f"Post-pipeline script failed: {script}")
    log.info("%s completed OK", script)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Import CryptoAPI-Bench, Juliet, and Nuclei patterns into HexVibe patterns.md",
    )
    p.add_argument(
        "--target",
        choices=tuple(EXTRACTORS.keys()) + ("all",),
        default="all",
        help="Dataset to ingest (default: all)",
    )
    p.add_argument("--crypto-repo", type=Path, default=None, help="Local CryptoAPI-Bench path")
    p.add_argument("--juliet-repo", type=Path, default=None, help="Local juliet-test-suite-c path")
    p.add_argument("--nuclei-repo", type=Path, default=None, help="Local nuclei-templates path")
    p.add_argument(
        "--cache-dir",
        type=Path,
        default=CACHE_DIR,
        help="Clone cache directory (default: .cache/advanced-datasets)",
    )
    p.add_argument("--dry-run", action="store_true", help="Parse and log only; do not write files")
    p.add_argument("--skip-sync", action="store_true", help="Do not run scripts/sync_semgrep.py")
    p.add_argument("--limit", type=int, default=None, help="Process only the first N source files")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logging(args.verbose)
    global CACHE_DIR
    CACHE_DIR = args.cache_dir.resolve()

    log.info("HexVibe advanced dataset ingest (root=%s)", ROOT)
    targets = list(EXTRACTORS.keys()) if args.target == "all" else [args.target]
    all_patterns: list[DatasetPattern] = []

    try:
        if "crypto" in targets:
            repo = resolve_repo(args.crypto_repo, CRYPTO_REPO_URL, "CryptoAPI-Bench", CRYPTO_ZIP_URL)
            all_patterns.extend(CryptoApiExtractor(repo, limit=args.limit).extract())
        if "juliet" in targets:
            repo = resolve_repo(args.juliet_repo, JULIET_REPO_URL, "juliet-test-suite-c", JULIET_ZIP_URL)
            all_patterns.extend(JulietExtractor(repo, limit=args.limit).extract())
        if "nuclei" in targets:
            repo = resolve_repo(args.nuclei_repo, NUCLEI_REPO_URL, "nuclei-templates", NUCLEI_ZIP_URL)
            all_patterns.extend(NucleiExtractor(repo, limit=args.limit).extract())

        imported = write_patterns(all_patterns, dry_run=args.dry_run)
        if imported and not args.dry_run:
            run_post_pipeline(args.skip_sync)
        elif imported == 0:
            log.info("No new patterns imported; post-pipeline not invoked")
        else:
            log.info("Dry-run complete (%d would import)", imported)

        log.info("Done. New patterns: %d / candidates: %d", imported, len(all_patterns))
        return 0
    except Exception:
        log.exception("Advanced dataset ingest failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
