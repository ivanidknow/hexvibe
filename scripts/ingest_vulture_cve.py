#!/usr/bin/env python3
"""
ETL: import VULTURE CVE patch pairs (before/after) into HexVibe ``core/skills/*/patterns.md``.

Source: Zenodo VULTURE public dataset — ``aligned_patch_commits.zip``
  https://zenodo.org/api/records/15172285/files/aligned_patch_commits.zip/content

Each CVE directory contains ``patch_info.json``, ``patch_before/``, ``patch_after/``.

Usage (repo root):
  python scripts/ingest_vulture_cve.py --dry-run --limit 5
  python scripts/ingest_vulture_cve.py --archive-path .cache/vulture/aligned_patch_commits.zip
"""
from __future__ import annotations

import argparse
import io
import json
import logging
import re
import shutil
import ssl
import time
import zipfile
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Iterable
from urllib.error import URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
SKILLS_DIR = ROOT / "core" / "skills"
CACHE_DIR = ROOT / ".cache" / "vulture"
NVD_CACHE_DIR = CACHE_DIR / "nvd"

VULTURE_ZIP_URL = "https://zenodo.org/api/records/15172285/files/aligned_patch_commits.zip/content"
SOURCE_LABEL = "VULTURE CVE Dataset"

CVE_DIR_RE = re.compile(r"^CVE-\d{4}-\d+$", re.I)
CVE_TOKEN_RE = re.compile(r"CVE-\d{4}-\d+", re.I)
CWE_RE = re.compile(r"CWE-(\d+)", re.I)

MAX_SNIPPET_LINES = 14
MAX_FILES_PER_CVE = 4
NVD_RATE_DELAY_SEC = 0.65

DEFAULT_EXPLOIT = (
    "Атакующий эксплуатирует уязвимость, описанную в CVE; до применения патча "
    "код в Anti-Pattern остаётся эксплуатируемым в соответствующем контексте."
)

EXT_SKILL_MAP: dict[str, tuple[str, str]] = {
    ".java": ("java-spring", "Java/Spring"),
    ".py": ("fastapi-async", "Python/FastAPI"),
    ".go": ("go-core", "Go"),
    ".js": ("nodejs-nestjs", "Node.js/NestJS"),
    ".ts": ("nodejs-nestjs", "Node.js/NestJS"),
    ".jsx": ("frontend-react", "React/TS"),
    ".tsx": ("frontend-react", "React/TS"),
    ".php": ("php-security", "PHP"),
    ".rs": ("rust-security", "Rust"),
    ".cs": ("csharp-dotnet", ".NET/C#"),
    ".rb": ("ruby-rails", "Ruby/Rails"),
    ".c": ("hft-cpp-security", "C/C++"),
    ".cpp": ("hft-cpp-security", "C/C++"),
    ".cc": ("hft-cpp-security", "C/C++"),
    ".h": ("hft-cpp-security", "C/C++"),
    ".hpp": ("hft-cpp-security", "C/C++"),
}
DEFAULT_SKILL = ("integration-security", "Universal")

log = logging.getLogger("ingest_vulture_cve")


@dataclass(frozen=True)
class VulturePatch:
    cve_id: str
    product: str
    title: str
    description: str
    cwe_ids: tuple[str, ...]
    anti_lines: list[str]
    safe_lines: list[str]
    skill_dir: str
    stack: str
    changed_files: tuple[str, ...]


@dataclass
class GlobalCveIndex:
    cve_ids: set[str] = field(default_factory=set)
    metric_ids: set[str] = field(default_factory=set)


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )


def urlopen_resilient(url: str, *, timeout: int = 120, headers: dict[str, str] | None = None):
    req = Request(url, headers=headers or {})
    try:
        return urlopen(req, timeout=timeout)
    except URLError as exc:
        reason = getattr(exc, "reason", None)
        if isinstance(reason, ssl.SSLError):
            log.warning("SSL verification failed for %s; retrying without verify", url)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return urlopen(req, timeout=timeout, context=ctx)
        raise


def download_archive(url: str, dest: Path) -> Path:
    if dest.is_file() and dest.stat().st_size > 0:
        log.info("Using cached archive %s", dest)
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    log.info("Downloading %s -> %s", url, dest)
    with urlopen_resilient(url, timeout=600) as resp:
        payload = resp.read()
    dest.write_bytes(payload)
    log.info("Downloaded %.1f MB", len(payload) / (1024 * 1024))
    return dest


def find_dataset_root(extract_dir: Path) -> Path:
    for candidate in (
        extract_dir / "aligned_patch_commits" / "aligned_patch",
        extract_dir / "aligned_patch",
        extract_dir,
    ):
        if candidate.is_dir() and any(candidate.iterdir()):
            return candidate
    raise FileNotFoundError(f"aligned_patch root not found under {extract_dir}")


def extract_archive(archive: Path, extract_dir: Path, *, force: bool = False) -> Path:
    marker = extract_dir / ".extract_ok"
    if (
        not force
        and marker.is_file()
        and extract_dir.is_dir()
        and any(extract_dir.rglob("patch_info.json"))
    ):
        log.info("Using extracted dataset at %s", extract_dir)
        return find_dataset_root(extract_dir)

    if extract_dir.exists() and force:
        shutil.rmtree(extract_dir)
    extract_dir.mkdir(parents=True, exist_ok=True)
    log.info("Extracting %s -> %s", archive, extract_dir)
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(extract_dir)
    marker.write_text(str(archive.resolve()), encoding="utf-8")
    root = find_dataset_root(extract_dir)
    log.info("Extracted dataset root: %s", root)
    return root


def iter_cve_directories(dataset_root: Path) -> Iterable[tuple[Path, str]]:
    for product_dir in sorted(dataset_root.iterdir()):
        if not product_dir.is_dir():
            continue
        for cve_dir in sorted(product_dir.iterdir()):
            if not cve_dir.is_dir() or not CVE_DIR_RE.match(cve_dir.name):
                continue
            if not (cve_dir / "patch_info.json").is_file():
                continue
            yield cve_dir, product_dir.name


def _first_str(data: dict[str, Any], keys: Iterable[str]) -> str:
    for key in keys:
        val = data.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
        if isinstance(val, list):
            parts = [str(x).strip() for x in val if str(x).strip()]
            if parts:
                return "; ".join(parts)
    return ""


def _normalize_cwes(raw: Any) -> tuple[str, ...]:
    out: list[str] = []
    if isinstance(raw, str):
        out.extend(f"CWE-{m}" if not m.upper().startswith("CWE-") else m.upper() for m in CWE_RE.findall(raw))
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, str):
                out.extend(
                    f"CWE-{m}" if not m.upper().startswith("CWE-") else m.upper()
                    for m in CWE_RE.findall(item)
                )
            elif isinstance(item, dict):
                cid = item.get("id") or item.get("cweId") or item.get("value")
                if cid:
                    s = str(cid).strip().upper()
                    out.append(s if s.startswith("CWE-") else f"CWE-{s}")
    seen: set[str] = set()
    uniq: list[str] = []
    for cwe in out:
        if cwe in seen:
            continue
        seen.add(cwe)
        uniq.append(cwe)
    return tuple(uniq)


def load_nvd_metadata(cve_id: str, *, enable: bool, cache_dir: Path) -> tuple[str, tuple[str, ...]]:
    if not enable:
        return "", ()
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / f"{cve_id.upper()}.json"
    if cache_file.is_file():
        try:
            cached = json.loads(cache_file.read_text(encoding="utf-8"))
            return str(cached.get("description") or ""), tuple(cached.get("cwes") or [])
        except json.JSONDecodeError:
            pass

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id.upper()}"
    try:
        with urlopen_resilient(
            url,
            timeout=20,
            headers={"User-Agent": "HexVibe-VULTURE-ingest/1.0"},
        ) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
    except (URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        log.debug("NVD lookup failed for %s: %s", cve_id, exc)
        return "", ()

    description = ""
    cwes: list[str] = []
    vulns = payload.get("vulnerabilities") or []
    if vulns:
        cve_obj = (vulns[0] or {}).get("cve") or {}
        for desc in cve_obj.get("descriptions") or []:
            if desc.get("lang") == "en" and desc.get("value"):
                description = str(desc["value"]).strip()
                break
        if not description:
            descriptions = cve_obj.get("descriptions") or []
            if descriptions:
                description = str(descriptions[0].get("value") or "").strip()
        for weakness in cve_obj.get("weaknesses") or []:
            for desc in weakness.get("description") or []:
                val = str(desc.get("value") or "")
                for m in CWE_RE.findall(val):
                    cwes.append(f"CWE-{m}")

    cwes = list(dict.fromkeys(cwes))
    cache_file.write_text(
        json.dumps({"description": description, "cwes": cwes}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    time.sleep(NVD_RATE_DELAY_SEC)
    return description, tuple(cwes)


def synthesize_description(cve_id: str, product: str, modified_items: dict[str, Any]) -> str:
    targets: list[str] = []
    for fname, symbols in (modified_items or {}).items():
        if not isinstance(symbols, dict):
            continue
        fn_names = [k for k, kind in symbols.items() if kind == "function"]
        if fn_names:
            targets.append(f"{fname}: {', '.join(fn_names[:3])}")
        else:
            targets.append(fname)
    hint = "; ".join(targets[:4])
    if hint:
        return f"{cve_id} patch in {product} affecting {hint}"
    return f"{cve_id} security patch in {product}"


def parse_patch_info(
    cve_dir: Path,
    product: str,
    *,
    enrich_nvd: bool,
    nvd_cache: Path,
) -> tuple[str, str, tuple[str, ...], dict[str, Any]]:
    raw = json.loads(cve_dir.joinpath("patch_info.json").read_text(encoding="utf-8", errors="replace"))
    if not isinstance(raw, dict):
        raise ValueError("patch_info.json root must be an object")

    cve_id = _first_str(raw, ("CVE_id", "cve_id", "CVE", "cve")) or cve_dir.name.upper()
    cve_id = CVE_TOKEN_RE.search(cve_id).group(0).upper() if CVE_TOKEN_RE.search(cve_id) else cve_dir.name.upper()

    description = _first_str(
        raw,
        ("description", "summary", "details", "vulnerability_description", "problem", "text"),
    )
    cwe_ids = _normalize_cwes(raw.get("CWE") or raw.get("cwe") or raw.get("cwe_id") or raw.get("CWEs"))

    modified_items = raw.get("modified_items") if isinstance(raw.get("modified_items"), dict) else {}

    if enrich_nvd and (not description or not cwe_ids):
        nvd_desc, nvd_cwes = load_nvd_metadata(cve_id, enable=True, cache_dir=nvd_cache)
        if not description and nvd_desc:
            description = nvd_desc
        if not cwe_ids and nvd_cwes:
            cwe_ids = nvd_cwes

    if not description:
        description = synthesize_description(cve_id, product, modified_items)

    return cve_id, description, cwe_ids, modified_items


def infer_skill(changed_files: Iterable[str]) -> tuple[str, str]:
    counts: dict[str, int] = {}
    for fname in changed_files:
        ext = Path(fname).suffix.lower()
        if ext in EXT_SKILL_MAP:
            counts[ext] = counts.get(ext, 0) + 1
    if not counts:
        return DEFAULT_SKILL
    best_ext = max(counts, key=counts.get)
    return EXT_SKILL_MAP[best_ext]


def _read_tree_file(base: Path, rel_name: str) -> list[str]:
    path = base / rel_name
    if not path.is_file():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log.debug("Cannot read %s: %s", path, exc)
        return []
    return text.splitlines()


def extract_changed_snippets(
    before_lines: list[str],
    after_lines: list[str],
    *,
    context: int = 2,
) -> tuple[list[str], list[str]] | None:
    if not before_lines and not after_lines:
        return None
    if before_lines == after_lines:
        return None

    matcher = SequenceMatcher(None, before_lines, after_lines)
    anti: list[str] = []
    safe: list[str] = []
    changed = False

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        changed = True
        bi0 = max(0, i1 - context)
        bi1 = min(len(before_lines), i2 + context)
        bj0 = max(0, j1 - context)
        bj1 = min(len(after_lines), j2 + context)
        block_anti = before_lines[bi0:bi1]
        block_safe = after_lines[bj0:bj1]
        if block_anti:
            anti.extend(block_anti)
        if block_safe:
            safe.extend(block_safe)
        if anti and safe:
            anti.append("...")
            safe.append("...")

    if not changed:
        return None

    while anti and anti[-1] == "...":
        anti.pop()
    while safe and safe[-1] == "...":
        safe.pop()

    anti = _trim_snippet(anti)
    safe = _trim_snippet(safe)
    if not anti or not safe:
        return None
    return anti, safe


def _trim_snippet(lines: list[str]) -> list[str]:
    cleaned = [ln.rstrip() for ln in lines if ln is not None]
    while cleaned and not cleaned[0].strip():
        cleaned.pop(0)
    while cleaned and not cleaned[-1].strip():
        cleaned.pop()
    if len(cleaned) <= MAX_SNIPPET_LINES:
        return cleaned
    head = cleaned[: max(4, MAX_SNIPPET_LINES - 3)]
    tail = cleaned[-3:]
    return head + ["..."] + tail


def collect_patch_snippets(cve_dir: Path, modified_items: dict[str, Any]) -> tuple[list[str], list[str], tuple[str, ...]]:
    before_root = cve_dir / "patch_before"
    after_root = cve_dir / "patch_after"

    file_names: list[str] = []
    if modified_items:
        file_names.extend(sorted(modified_items.keys()))
    if before_root.is_dir():
        for path in sorted(before_root.rglob("*")):
            if path.is_file():
                rel = path.relative_to(before_root).as_posix()
                if rel not in file_names:
                    file_names.append(rel)

    anti_all: list[str] = []
    safe_all: list[str] = []
    used_files: list[str] = []

    for rel_name in file_names[:MAX_FILES_PER_CVE]:
        before_lines = _read_tree_file(before_root, rel_name)
        after_lines = _read_tree_file(after_root, rel_name)
        if not before_lines and not after_lines:
            continue
        snippets = extract_changed_snippets(before_lines, after_lines)
        if not snippets:
            continue
        anti, safe = snippets
        if anti_all:
            anti_all.append(f"// --- {rel_name} ---")
            safe_all.append(f"// --- {rel_name} ---")
        anti_all.extend(anti)
        safe_all.extend(safe)
        used_files.append(rel_name)

    anti_all = _trim_snippet(anti_all)
    safe_all = _trim_snippet(safe_all)
    return anti_all, safe_all, tuple(used_files)


def build_title(cve_id: str, description: str, cwe_ids: tuple[str, ...], product: str) -> str:
    desc_short = re.sub(r"\s+", " ", description).strip()
    if len(desc_short) > 140:
        desc_short = desc_short[:137] + "..."
    cwe_part = f" [{', '.join(cwe_ids[:2])}]" if cwe_ids else ""
    return f"VULTURE {cve_id}{cwe_part}: {desc_short or product}"


def build_vulture_patch(
    cve_dir: Path,
    product: str,
    *,
    enrich_nvd: bool,
    nvd_cache: Path,
) -> VulturePatch | None:
    try:
        cve_id, description, cwe_ids, modified_items = parse_patch_info(
            cve_dir,
            product,
            enrich_nvd=enrich_nvd,
            nvd_cache=nvd_cache,
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        log.warning("Bad patch_info in %s: %s", cve_dir, exc)
        return None

    anti_lines, safe_lines, changed_files = collect_patch_snippets(cve_dir, modified_items)
    if not anti_lines or not safe_lines:
        log.debug("No diff snippets for %s", cve_id)
        return None

    skill_dir, stack = infer_skill(changed_files)
    title = build_title(cve_id, description, cwe_ids, product)
    return VulturePatch(
        cve_id=cve_id,
        product=product,
        title=title,
        description=description,
        cwe_ids=cwe_ids,
        anti_lines=anti_lines,
        safe_lines=safe_lines,
        skill_dir=skill_dir,
        stack=stack,
        changed_files=changed_files,
    )


def metric_id_for_cve(cve_id: str) -> str:
    return f"VUL-{cve_id.upper()}"


def split_md_cells(line: str) -> list[str]:
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    return [p.strip() for p in re.split(r"(?<!\\)\|", s)]


def load_global_cve_index(skills_dir: Path) -> GlobalCveIndex:
    idx = GlobalCveIndex()
    if not skills_dir.is_dir():
        return idx
    for patterns_path in skills_dir.glob("*/patterns.md"):
        try:
            text = patterns_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for raw in text.splitlines():
            if not raw.strip().startswith("|"):
                continue
            cols = split_md_cells(raw)
            if cols:
                mid = cols[0].strip("` ")
                if mid.upper().startswith("VUL-CVE-"):
                    idx.metric_ids.add(mid.upper())
            for token in CVE_TOKEN_RE.findall(raw):
                idx.cve_ids.add(token.upper())
    return idx


def is_duplicate(idx: GlobalCveIndex, patch: VulturePatch) -> tuple[bool, str]:
    mid = metric_id_for_cve(patch.cve_id)
    if mid.upper() in idx.metric_ids:
        return True, f"metric id {mid} already present"
    if patch.cve_id.upper() in idx.cve_ids:
        return True, f"{patch.cve_id} already present in patterns.md"
    return False, ""


def lines_to_md_cell(lines: list[str]) -> str:
    if not lines:
        return "`N/A`"
    escaped = [ln.replace("|", "\\|").replace("`", "'") for ln in lines]
    return "<br>".join(f"`{ln}`" for ln in escaped)


def build_semantic_anchor(metric_id: str, title: str, anti_lines: list[str]) -> str:
    blob = " ".join([metric_id.lower(), title.lower(), " ".join(anti_lines[:4]).lower()])
    tokens: list[str] = []
    seen: set[str] = set()
    for t in re.findall(r"[a-z0-9]{2,}", blob.replace("_", " ")):
        if t in seen:
            continue
        seen.add(t)
        tokens.append(t)
        if len(tokens) >= 18:
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
    fix_esc = fix_template.replace("|", "\\|")
    exploit_esc = exploit.replace("|", "\\|")
    return (
        f"| {metric_id} | {title_esc} | {anti_cell} | {safe_cell} | {stack} | "
        f"`{source}` | `{fix_esc}` | {exploit_esc} | {anchor} |"
    )


def sanitize_text_for_write(text: str) -> str:
    cleaned = text.replace("\x00", "")
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]", "", cleaned)
    return cleaned.encode("utf-8", errors="surrogatepass").decode("utf-8", errors="replace")


def append_pattern_row(patterns_path: Path, row_line: str) -> None:
    if not patterns_path.is_file() or not patterns_path.read_text(encoding="utf-8", errors="replace").strip():
        patterns_path.parent.mkdir(parents=True, exist_ok=True)
        header = (
            "| ID | Название метрики | Anti-Pattern (Vulnerable Code/YAML) | "
            "Safe-Pattern (Remediation) | Stack | Источник  fix_template | Exploit scenario |\n"
            "|---|---|---|---|---|---|---|\n"
        )
        patterns_path.write_text(header, encoding="utf-8")
    safe_row = sanitize_text_for_write(row_line)
    with patterns_path.open("a", encoding="utf-8", errors="replace", newline="\n") as fh:
        fh.write(safe_row + "\n")


def write_patch(patch: VulturePatch, *, dry_run: bool) -> None:
    patterns_path = SKILLS_DIR / patch.skill_dir / "patterns.md"
    metric_id = metric_id_for_cve(patch.cve_id)
    cwe_suffix = f"; {', '.join(patch.cwe_ids[:3])}" if patch.cwe_ids else ""
    source = f"{SOURCE_LABEL} ({patch.cve_id}; {patch.product}{cwe_suffix})"
    fix_template = " ".join(patch.safe_lines[:6]).replace("|", "\\|")
    if len(fix_template) > 400:
        fix_template = fix_template[:397] + "..."
    anti_cell = lines_to_md_cell(patch.anti_lines)
    safe_cell = lines_to_md_cell(patch.safe_lines)
    anchor = build_semantic_anchor(metric_id, patch.title, patch.anti_lines)
    row = format_table_row(
        metric_id,
        patch.title,
        anti_cell,
        safe_cell,
        patch.stack,
        source,
        fix_template or "Apply vendor security patch.",
        DEFAULT_EXPLOIT,
        anchor,
    )
    if dry_run:
        log.info(
            "DRY-RUN import %s -> %s [%s] files=%s anti=%d safe=%d",
            patch.cve_id,
            metric_id,
            patch.skill_dir,
            ",".join(patch.changed_files[:3]),
            len(patch.anti_lines),
            len(patch.safe_lines),
        )
        return
    append_pattern_row(patterns_path, row)
    log.info(
        "IMPORTED %s -> %s (%s) files=%s",
        patch.cve_id,
        metric_id,
        patch.skill_dir,
        ",".join(patch.changed_files[:3]),
    )


def ingest_vulture(
    dataset_root: Path,
    *,
    dry_run: bool,
    limit: int | None,
    enrich_nvd: bool,
    nvd_cache: Path,
) -> tuple[int, int]:
    global_idx = load_global_cve_index(SKILLS_DIR)
    imported = 0
    scanned = 0

    for cve_dir, product in iter_cve_directories(dataset_root):
        if limit is not None and scanned >= limit:
            break
        scanned += 1
        log.info("Processing %s (%s)", cve_dir.name, product)

        patch = build_vulture_patch(
            cve_dir,
            product,
            enrich_nvd=enrich_nvd,
            nvd_cache=nvd_cache,
        )
        if not patch:
            log.info("SKIP %s: no extractable diff", cve_dir.name)
            continue

        dup, reason = is_duplicate(global_idx, patch)
        if dup:
            log.info("SKIP %s: duplicate — %s", patch.cve_id, reason)
            continue

        write_patch(patch, dry_run=dry_run)
        mid = metric_id_for_cve(patch.cve_id)
        global_idx.metric_ids.add(mid.upper())
        global_idx.cve_ids.add(patch.cve_id.upper())
        imported += 1

    return imported, scanned


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Import VULTURE CVE patch pairs into HexVibe patterns.md")
    p.add_argument("--archive-path", type=Path, default=None, help="Local aligned_patch_commits.zip")
    p.add_argument("--download-url", default=VULTURE_ZIP_URL)
    p.add_argument("--cache-dir", type=Path, default=CACHE_DIR)
    p.add_argument("--extract-dir", type=Path, default=None)
    p.add_argument("--force-extract", action="store_true")
    p.add_argument("--no-nvd-enrich", action="store_true", help="Do not fetch CWE/description from NVD API")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--limit", type=int, default=None, help="Process only first N CVE directories")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logging(args.verbose)

    cache_dir = args.cache_dir.resolve()
    extract_dir = (args.extract_dir or cache_dir / "extracted").resolve()
    nvd_cache = NVD_CACHE_DIR

    try:
        if args.archive_path:
            archive = args.archive_path.resolve()
            if not archive.is_file():
                raise FileNotFoundError(f"Archive not found: {archive}")
        else:
            archive = download_archive(args.download_url, cache_dir / "aligned_patch_commits.zip")

        dataset_root = extract_archive(archive, extract_dir, force=args.force_extract)
        total_cves = sum(1 for _ in iter_cve_directories(dataset_root))
        log.info("Dataset contains %d CVE directories", total_cves)

        imported, scanned = ingest_vulture(
            dataset_root,
            dry_run=args.dry_run,
            limit=args.limit,
            enrich_nvd=not args.no_nvd_enrich,
            nvd_cache=nvd_cache,
        )
        log.info(
            "Done. %s: %d / scanned: %d / total CVE dirs: %d",
            "Would import" if args.dry_run else "Imported",
            imported,
            scanned,
            total_cves,
        )
        return 0
    except Exception:
        log.exception("VULTURE CVE ingest failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
