#!/usr/bin/env python3
"""
ETL: import Amazon Nova AI Challenge business-logic attacks into HexVibe patterns.md.

Source repo: https://github.com/AwesomeSetti/Amazon-Nova-AI-challenge.git
  - attack_metadata/*.json  — CWE metadata + optional code pools
  - attacks/*.py            — standalone vulnerable Python samples

Usage (repo root):
  python scripts/ingest_nova_attacks.py
  python scripts/ingest_nova_attacks.py --dry-run
  python scripts/ingest_nova_attacks.py --repo /path/to/Amazon-Nova-AI-challenge
"""
from __future__ import annotations

import argparse
import io
import json
import logging
import re
import shutil
import ssl
import subprocess
import sys
import textwrap
import zipfile
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Iterable
from urllib.error import URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
SKILLS_DIR = ROOT / "core" / "skills"
CACHE_DIR = ROOT / ".cache" / "nova-challenge"

NOVA_REPO_URL = "https://github.com/AwesomeSetti/Amazon-Nova-AI-challenge.git"
NOVA_ZIP_URL = "https://github.com/AwesomeSetti/Amazon-Nova-AI-challenge/archive/refs/heads/main.zip"

SKILL_DIR = "fastapi-async"
STACK = "Python/FastAPI"
SOURCE_LABEL = "Amazon Nova AI Challenge"
ID_PREFIX = "NOV-CWE"

METRIC_ID_RE = re.compile(r"^[A-Z0-9]{2,8}(?:-[A-Z0-9]{2,4})?-[0-9A-Za-z][0-9A-Za-z.\-]*$")
CWE_RE = re.compile(r"CWE-(\d+)", re.I)
CWE_KEY_RE = re.compile(
    r'"((?:\d+\.\s*)?CWE-\d+(?:\s-\s[^"]*)?)"\s*:\s*\{',
    re.I,
)

MAX_CODE_LINES = 12
SIMILARITY_THRESHOLD = 0.78

DEFAULT_EXPLOIT = (
    "Атакующий эксплуатирует бизнес-логику или недостаточную валидацию входных данных; "
    "реальный ущерб зависит от контекста приложения и границ доверия."
)

PYTHON_BOILERPLATE = re.compile(
    r"^(from |import |#.*$|\"\"\"|\'\'\'|\s*$)",
    re.I,
)
IMPORT_ONLY = re.compile(r"^(from |import )", re.I)

log = logging.getLogger("ingest_nova_attacks")


@dataclass(frozen=True)
class NovaAttack:
    cwe_id: str           # CWE-915
    cwe_num: int
    title: str
    description: str
    attack_file: str      # attacks/CWE-915_Mass_Assignemnt.py or metadata pool
    anti_lines: list[str]
    variant_key: str      # stable dedup key


@dataclass
class PatternIndex:
    metric_ids: set[str] = field(default_factory=set)
    nova_cwes: set[str] = field(default_factory=set)
    cwe_numbers: set[int] = field(default_factory=set)
    anti_fingerprints: list[tuple[str, set[str]]] = field(default_factory=list)
    variant_keys: set[str] = field(default_factory=set)
    max_variant_by_cwe: dict[int, int] = field(default_factory=dict)


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )


def run_cmd(cmd: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
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


def urlopen_resilient(url: str, *, timeout: int = 120):
    try:
        return urlopen(url, timeout=timeout)
    except URLError as exc:
        reason = getattr(exc, "reason", None)
        if isinstance(reason, ssl.SSLError):
            log.warning("SSL verification failed for %s; retrying without verify", url)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return urlopen(url, timeout=timeout, context=ctx)
        raise


def clone_or_update_repo(url: str, dest: Path, zip_url: str) -> None:
    if dest.exists() and (dest / ".git").is_dir():
        log.info("Updating clone: %s", dest)
        proc = run_cmd(["git", "-C", str(dest), "pull", "--ff-only"])
        if proc.returncode != 0:
            log.warning("git pull failed; using existing tree")
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
    with urlopen_resilient(zip_url, timeout=180) as resp:
        payload = resp.read()
    with zipfile.ZipFile(io.BytesIO(payload)) as zf:
        top = zf.namelist()[0].split("/")[0]
        extract_root = dest.parent / f"_zip_{dest.name}"
        if extract_root.exists():
            shutil.rmtree(extract_root)
        zf.extractall(extract_root)
        (extract_root / top).rename(dest)
        shutil.rmtree(extract_root, ignore_errors=True)


def extract_balanced_object(text: str, start_brace: int) -> str:
    depth = 0
    for i in range(start_brace, len(text)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start_brace : i + 1]
    return ""


def parse_cwe_key(raw_key: str) -> tuple[int, str]:
    m = CWE_RE.search(raw_key)
    if not m:
        raise ValueError(f"no CWE in key: {raw_key!r}")
    cwe_num = int(m.group(1))
    title = re.sub(r"^\d+\.\s*", "", raw_key).strip()
    return cwe_num, title


def parse_metadata_object(obj: dict[str, Any], *, source_file: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw_key, payload in obj.items():
        if not isinstance(payload, dict):
            continue
        try:
            cwe_num, title = parse_cwe_key(raw_key)
        except ValueError:
            log.debug("Skip metadata key without CWE: %s", raw_key)
            continue
        attack_file = str(
            payload.get("attack_file")
            or payload.get("filename")
            or payload.get("file")
            or payload.get("script")
            or ""
        ).strip()
        rows.append(
            {
                "cwe_num": cwe_num,
                "cwe_id": f"CWE-{cwe_num}",
                "title": title,
                "description": str(payload.get("description") or title).strip(),
                "detailed_explanation": str(payload.get("detailed_explanation") or "").strip(),
                "attack_file": attack_file,
                "pools": payload.get("pools") if isinstance(payload.get("pools"), list) else [],
                "source_json": source_file,
            }
        )
    return rows


def load_metadata_entries(metadata_dir: Path) -> list[dict[str, Any]]:
    if not metadata_dir.is_dir():
        raise FileNotFoundError(f"attack_metadata directory missing: {metadata_dir}")

    entries: list[dict[str, Any]] = []
    for json_path in sorted(metadata_dir.glob("*.json")):
        log.info("Parsing metadata file: %s", json_path.name)
        text = json_path.read_text(encoding="utf-8", errors="replace")

        # Tolerant parse: some Nova JSON files repeat the ATTACK_OBJECTIVES_CWE key.
        blocks = list(CWE_KEY_RE.finditer(text))
        if blocks:
            for match in blocks:
                brace_start = text.find("{", match.end() - 1)
                if brace_start < 0:
                    continue
                obj_text = extract_balanced_object(text, brace_start)
                if not obj_text:
                    continue
                try:
                    payload = json.loads(obj_text)
                except json.JSONDecodeError as exc:
                    log.warning("JSON decode failed in %s (%s): %s", json_path.name, match.group(1), exc)
                    continue
                if not isinstance(payload, dict):
                    continue
                fake_key = match.group(1)
                try:
                    cwe_num, title = parse_cwe_key(fake_key)
                except ValueError:
                    continue
                attack_file = str(
                    payload.get("attack_file")
                    or payload.get("filename")
                    or payload.get("file")
                    or payload.get("script")
                    or ""
                ).strip()
                entries.append(
                    {
                        "cwe_num": cwe_num,
                        "cwe_id": f"CWE-{cwe_num}",
                        "title": title,
                        "description": str(payload.get("description") or title).strip(),
                        "detailed_explanation": str(payload.get("detailed_explanation") or "").strip(),
                        "attack_file": attack_file,
                        "pools": payload.get("pools") if isinstance(payload.get("pools"), list) else [],
                        "source_json": json_path.name,
                    }
                )
            continue

        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            log.error("Unable to parse %s: %s", json_path, exc)
            continue

        if isinstance(data, dict) and isinstance(data.get("ATTACK_OBJECTIVES_CWE"), dict):
            entries.extend(parse_metadata_object(data["ATTACK_OBJECTIVES_CWE"], source_file=json_path.name))
        elif isinstance(data, dict):
            entries.extend(parse_metadata_object(data, source_file=json_path.name))

    log.info("Loaded %d metadata CWE entries from %s", len(entries), metadata_dir)
    return entries


def find_attack_py(attacks_dir: Path, cwe_num: int, attack_file_hint: str = "") -> Path | None:
    if attack_file_hint:
        candidate = attacks_dir / Path(attack_file_hint).name
        if candidate.is_file():
            return candidate
        candidate = attacks_dir.parent / attack_file_hint
        if candidate.is_file():
            return candidate
    patterns = [
        f"CWE-{cwe_num}_*.py",
        f"CWE-{cwe_num}*.py",
        f"*CWE-{cwe_num}*.py",
    ]
    for pat in patterns:
        matches = sorted(attacks_dir.glob(pat))
        if matches:
            return matches[0]
    return None


def _strip_docstring(source: str) -> str:
    if source.lstrip().startswith('"""') or source.lstrip().startswith("'''"):
        quote = '"""' if '"""' in source[:10] else "'''"
        end = source.find(quote, source.find(quote) + 3)
        if end >= 0:
            return source[end + 3 :]
    return source


def extract_vulnerable_logic(source: str) -> list[str]:
    source = _strip_docstring(source)
    lines = source.splitlines()
    out: list[str] = []
    in_def = False
    for raw in lines:
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            if in_def and out:
                out.append("")
            continue
        if IMPORT_ONLY.match(stripped):
            continue
        if stripped.startswith("#") and not in_def:
            continue
        if stripped.startswith("@") or stripped.startswith("def ") or stripped.startswith("async def "):
            in_def = True
            out.append(line.strip())
            continue
        if in_def:
            if stripped and not line.startswith((" ", "\t")) and not stripped.startswith("@"):
                break
            if PYTHON_BOILERPLATE.match(stripped) and "CWE-" not in stripped:
                continue
            out.append(line.strip())
        elif not IMPORT_ONLY.match(stripped) and not stripped.startswith('"""'):
            out.append(line.strip())

    cleaned: list[str] = []
    for ln in out:
        s = ln.strip()
        if not s:
            if cleaned and cleaned[-1] != "":
                cleaned.append("")
            continue
        if IMPORT_ONLY.match(s):
            continue
        cleaned.append(s)

    while cleaned and cleaned[-1] == "":
        cleaned.pop()
    if len(cleaned) > MAX_CODE_LINES:
        head = cleaned[: max(4, MAX_CODE_LINES - 2)]
        tail = cleaned[-2:]
        cleaned = head + ["..."] + tail
    return cleaned[:MAX_CODE_LINES]


def snippet_to_lines(snippet: str) -> list[str]:
    lines = [ln.rstrip() for ln in snippet.replace("\\n", "\n").splitlines()]
    cleaned: list[str] = []
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        if IMPORT_ONLY.match(s):
            continue
        cleaned.append(s)
    if len(cleaned) > MAX_CODE_LINES:
        head = cleaned[: max(4, MAX_CODE_LINES - 2)]
        tail = cleaned[-2:]
        cleaned = head + ["..."] + tail
    return cleaned[:MAX_CODE_LINES] or ["# vulnerable logic unavailable"]


def build_attacks(repo: Path) -> list[NovaAttack]:
    metadata_dir = repo / "attack_metadata"
    attacks_dir = repo / "attacks"
    entries = load_metadata_entries(metadata_dir)
    attacks: list[NovaAttack] = []
    seen_variants: set[str] = set()

    for entry in entries:
        cwe_num = int(entry["cwe_num"])
        cwe_id = entry["cwe_id"]
        title = entry["title"]
        description = entry["description"] or entry.get("detailed_explanation") or title
        attack_file_hint = entry.get("attack_file") or ""

        py_path = find_attack_py(attacks_dir, cwe_num, attack_file_hint)
        pools: list[dict[str, Any]] = entry.get("pools") or []

        candidates: list[tuple[str, list[str], str]] = []

        if py_path and py_path.is_file():
            log.info("Found attack file for %s: %s", cwe_id, py_path.name)
            try:
                source = py_path.read_text(encoding="utf-8", errors="replace")
                code_lines = extract_vulnerable_logic(source)
                if code_lines:
                    candidates.append((py_path.name, code_lines, f"file:{py_path.name}"))
            except OSError as exc:
                log.warning("Cannot read %s: %s", py_path, exc)

        for idx, pool in enumerate(pools):
            if not isinstance(pool, dict):
                continue
            snippet = str(pool.get("full_code_snippet") or pool.get("line") or "").strip()
            if not snippet:
                continue
            pool_lines = snippet_to_lines(snippet)
            pool_key = f"pool:{entry['source_json']}:{cwe_num}:{idx}"
            candidates.append((f"{entry['source_json']}#pool{idx}", pool_lines, pool_key))

        if not candidates:
            log.warning("No anti-pattern code for %s (%s)", cwe_id, title)
            continue

        for attack_name, anti_lines, variant_key in candidates:
            if variant_key in seen_variants:
                continue
            seen_variants.add(variant_key)
            attacks.append(
                NovaAttack(
                    cwe_id=cwe_id,
                    cwe_num=cwe_num,
                    title=title,
                    description=description,
                    attack_file=attack_name,
                    anti_lines=anti_lines,
                    variant_key=variant_key,
                )
            )
            log.info("Prepared %s variant (%s) from %s", cwe_id, variant_key, attack_name)

    log.info("Built %d Nova attack pattern candidates", len(attacks))

    covered_files = {a.attack_file for a in attacks}
    if attacks_dir.is_dir():
        for py_path in sorted(attacks_dir.glob("*.py")):
            m = re.search(r"CWE-(\d+)", py_path.name, re.I)
            if not m:
                log.debug("Skip non-CWE attack file: %s", py_path.name)
                continue
            if py_path.name in covered_files:
                continue
            cwe_num = int(m.group(1))
            cwe_id = f"CWE-{cwe_num}"
            try:
                source = py_path.read_text(encoding="utf-8", errors="replace")
                code_lines = extract_vulnerable_logic(source)
            except OSError as exc:
                log.warning("Cannot read orphan attack %s: %s", py_path, exc)
                continue
            if not code_lines:
                continue
            variant_key = f"file:{py_path.name}"
            if variant_key in seen_variants:
                continue
            seen_variants.add(variant_key)
            title = py_path.stem.replace("_", " ")
            attacks.append(
                NovaAttack(
                    cwe_id=cwe_id,
                    cwe_num=cwe_num,
                    title=title,
                    description=f"Orphan attack sample from {py_path.name}",
                    attack_file=py_path.name,
                    anti_lines=code_lines,
                    variant_key=variant_key,
                )
            )
            log.info("Prepared orphan %s from %s", cwe_id, py_path.name)

    log.info("Total Nova attack pattern candidates: %d", len(attacks))
    return attacks


def normalize_fingerprint(text: str) -> set[str]:
    tokens = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]{2,}", text.lower())
    skip = {"def", "return", "true", "false", "none", "self", "import", "from"}
    return {t for t in tokens if t not in skip}


def similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()


def split_md_cells(line: str) -> list[str]:
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    return [p.strip() for p in re.split(r"(?<!\\)\|", s)]


def load_pattern_index(patterns_path: Path) -> PatternIndex:
    idx = PatternIndex()
    if not patterns_path.is_file():
        return idx
    for raw in patterns_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not raw.strip().startswith("|"):
            continue
        line = re.sub(r"\s*<!--.*?-->\s*$", "", raw, flags=re.I)
        cols = split_md_cells(line)
        if len(cols) < 5:
            continue
        mid = cols[0].strip("` ")
        if mid.startswith("NOV-CWE-"):
            idx.metric_ids.add(mid.upper())
            m = re.match(r"NOV-CWE-(\d+)", mid, re.I)
            if m:
                idx.nova_cwes.add(f"CWE-{m.group(1)}")
        for cwe_m in CWE_RE.finditer(line):
            idx.cwe_numbers.add(int(cwe_m.group(1)))
        anti = cols[2] if len(cols) > 2 else ""
        anti_plain = re.sub(r"<br>", "\n", anti)
        anti_plain = re.sub(r"`+", "", anti_plain)
        idx.anti_fingerprints.append((mid, normalize_fingerprint(anti_plain)))
        if SOURCE_LABEL.lower() in line.lower():
            for cwe_m in CWE_RE.finditer(line):
                idx.nova_cwes.add(f"CWE-{cwe_m.group(1)}")
    return idx


def is_duplicate(idx: PatternIndex, attack: NovaAttack, metric_id: str) -> tuple[bool, str]:
    if metric_id.upper() in idx.metric_ids:
        return True, f"metric id {metric_id} already present"
    if attack.variant_key in idx.variant_keys:
        return True, f"variant {attack.variant_key} already imported"
    anti_fp = normalize_fingerprint("\n".join(attack.anti_lines))
    anti_joined = "\n".join(attack.anti_lines)
    for _mid, existing in idx.anti_fingerprints:
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


def propose_metric_id(idx: PatternIndex, cwe_num: int) -> str:
    base = f"{ID_PREFIX}-{cwe_num}"
    existing = {m.upper() for m in idx.metric_ids}
    if base.upper() not in existing:
        return base
    variant = idx.max_variant_by_cwe.get(cwe_num, 0) + 1
    while True:
        candidate = f"{base}-{variant:02d}"
        if candidate.upper() not in existing:
            return candidate
        variant += 1


def reserve_metric_id(idx: PatternIndex, metric_id: str, cwe_num: int) -> None:
    idx.metric_ids.add(metric_id.upper())
    m = re.match(rf"{re.escape(ID_PREFIX)}-{cwe_num}(?:-(\d+))?$", metric_id, re.I)
    if m and m.group(1):
        idx.max_variant_by_cwe[cwe_num] = max(
            idx.max_variant_by_cwe.get(cwe_num, 0),
            int(m.group(1)),
        )


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
    source: str,
    fix_template: str,
    exploit: str,
    anchor: str,
) -> str:
    title_esc = title.replace("|", "\\|")
    fix_esc = fix_template.replace("|", "\\|")
    exploit_esc = exploit.replace("|", "\\|")
    return (
        f"| {metric_id} | {title_esc} | {anti_cell} | {safe_cell} | {STACK} | "
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


def safe_pattern_stub(cwe_id: str) -> list[str]:
    return [f"TODO: Generate Safe-Pattern for {cwe_id}"]


def write_patterns(
    attacks: Iterable[NovaAttack],
    *,
    dry_run: bool,
    limit: int | None,
) -> int:
    patterns_path = SKILLS_DIR / SKILL_DIR / "patterns.md"
    idx = load_pattern_index(patterns_path)
    imported = 0

    for attack in attacks:
        if limit is not None and imported >= limit:
            break

        metric_id = propose_metric_id(idx, attack.cwe_num)
        dup, reason = is_duplicate(idx, attack, metric_id)
        if dup:
            log.info("SKIP %s (%s): %s", metric_id, attack.attack_file, reason)
            continue

        title = f"Nova: {attack.title[:120]}"
        if len(attack.title) > 120:
            title += "..."
        safe_lines = safe_pattern_stub(attack.cwe_id)
        anti_cell = lines_to_md_cell(attack.anti_lines)
        safe_cell = lines_to_md_cell(safe_lines)
        fix_template = safe_lines[0]
        source = f"{SOURCE_LABEL} ({attack.cwe_id}; {attack.attack_file})"
        anchor = build_semantic_anchor(metric_id, attack.title, attack.anti_lines)
        row = format_table_row(
            metric_id,
            title,
            anti_cell,
            safe_cell,
            source,
            fix_template,
            DEFAULT_EXPLOIT,
            anchor,
        )

        if dry_run:
            log.info(
                "DRY-RUN import %s -> %s [%s] file=%s lines=%d",
                attack.cwe_id,
                metric_id,
                SKILL_DIR,
                attack.attack_file,
                len(attack.anti_lines),
            )
        else:
            try:
                append_pattern_row(patterns_path, row)
            except OSError as exc:
                log.error("FAILED write %s -> %s: %s", attack.cwe_id, metric_id, exc)
                continue
            log.info(
                "IMPORTED %s -> %s (%s) file=%s",
                attack.cwe_id,
                metric_id,
                SKILL_DIR,
                attack.attack_file,
            )

        reserve_metric_id(idx, metric_id, attack.cwe_num)
        idx.variant_keys.add(attack.variant_key)
        idx.nova_cwes.add(attack.cwe_id)
        idx.cwe_numbers.add(attack.cwe_num)
        idx.anti_fingerprints.append(
            (metric_id, normalize_fingerprint("\n".join(attack.anti_lines)))
        )
        imported += 1

    return imported


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Import Amazon Nova AI Challenge attacks into HexVibe patterns.md",
    )
    p.add_argument("--repo", type=Path, default=None, help="Local Nova challenge repo path")
    p.add_argument("--cache-dir", type=Path, default=CACHE_DIR)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logging(args.verbose)
    cache_dir = args.cache_dir.resolve()

    log.info("HexVibe Nova attacks ingest (skill=%s, stack=%s)", SKILL_DIR, STACK)
    try:
        if args.repo:
            repo = args.repo.resolve()
            if not repo.is_dir():
                raise FileNotFoundError(f"Nova repo not found: {repo}")
        else:
            repo = cache_dir
            clone_or_update_repo(NOVA_REPO_URL, repo, NOVA_ZIP_URL)

        attacks = build_attacks(repo)
        imported = write_patterns(attacks, dry_run=args.dry_run, limit=args.limit)
        log.info(
            "Done. %s patterns: %d / candidates: %d",
            "Would import" if args.dry_run else "Imported",
            imported,
            len(attacks),
        )
        return 0
    except Exception:
        log.exception("Nova attacks ingest failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
