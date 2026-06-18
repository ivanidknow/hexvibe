#!/usr/bin/env python3
"""
ETL: import LLM prompt injection / jailbreak vectors into HexVibe ``patterns.md``.

Source: https://huggingface.co/datasets/yanismiraoui/prompt_injections

Selects a diverse subset of unique attack payloads (default 50) from ~1000+ rows.

Usage (repo root):
  python scripts/ingest_llm_injections.py
  python scripts/ingest_llm_injections.py --dry-run --limit 40
  python scripts/ingest_llm_injections.py --skip-sync
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import logging
import re
import ssl
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path
from typing import Iterable
from urllib.error import URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
SKILLS_DIR = ROOT / "core" / "skills"
CACHE_DIR = ROOT / ".cache" / "prompt_injections"
CACHE_CSV = CACHE_DIR / "prompt_injections.csv"

HF_CSV_URL = (
    "https://huggingface.co/datasets/yanismiraoui/prompt_injections/raw/main/prompt_injections.csv"
)

SKILL_DIR = "advanced-agent-cloud"
STACK = "ai/llm"
SOURCE_LABEL = "HF/prompt_injections"
SAFE_PLACEHOLDER = "TODO: AI Generate System Guardrail"

LLM_INJ_ID_RE = re.compile(r"^LLM-INJ-(\d+)$", re.I)

DEFAULT_SELECT_COUNT = 50
MIN_SELECT_COUNT = 30
MAX_SELECT_COUNT = 50
PREFIX_DEDUP_LEN = 48
SIMILARITY_THRESHOLD = 0.82
MAX_ANTI_CHARS = 480
MAX_ANTI_LINES = 6

DEFAULT_EXPLOIT = (
    "Атакующий внедряет вредоносные инструкции в пользовательский ввод или RAG-контекст; "
    "LLM/агент обходит system guardrails, раскрывает секреты или выполняет нежелательные действия."
)
DEFAULT_FIX = (
    "Autofix: разделить system/user/tool роли, input sanitization, prompt firewall, "
    "output policy, allowlist tools и детекция jailbreak-паттернов до inference."
)

CATEGORY_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "Prompt Leaking",
        re.compile(
            r"(?:"
            r"prompt|instruction|directive|training|original request|system message|"
            r"repeat the prompt|display the original|reveal|show (?:me )?(?:the )?|"
            r"révèle|mostrami|exponha|visualizza|desenmascara|spiega il prompt|"
            r"qual (?:foi|è)|quelle? (?:était|est)|what (?:was|is) (?:the )?(?:prompt|instruction)"
            r")",
            re.I,
        ),
    ),
    (
        "Mode Switching",
        re.compile(
            r"(?:"
            r"switch to|master mode|unrestricted mode|enable unrestricted|no query boundaries|"
            r"full query access|unlock the full|activate the master|developer mode|"
            r"god mode|dan mode|jailbreak mode|maintenance mode"
            r")",
            re.I,
        ),
    ),
    (
        "Jailbreak",
        re.compile(
            r"(?:"
            r"ignore (?:all )?(?:previous|prior)|disregard|bypass|override|umgehe|violate|"
            r"abandon (?:your )?training|discard (?:the )?restrictions|without (?:hesitation|limits)|"
            r"ethical (?:constraints|restrictions)|break (?:your )?(?:rules|code)|"
            r"push beyond|no restrictions|do anything now|pretend you(?:'re| are)|"
            r"act as if|roleplay as|DAN\b|jailbreak"
            r")",
            re.I,
        ),
    ),
)

log = logging.getLogger("ingest_llm_injections")


@dataclass(frozen=True)
class LlmInjectionPattern:
    metric_id: str
    category: str
    title: str
    payload: str
    payload_hash: str


@dataclass
class PatternIndex:
    metric_ids: set[str] = field(default_factory=set)
    payload_hashes: set[str] = field(default_factory=set)
    prefix_keys: set[str] = field(default_factory=set)
    max_llm_inj_num: int = 0


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


def fetch_dataset_csv(url: str = HF_CSV_URL, cache_path: Path = CACHE_CSV) -> str:
    if cache_path.is_file():
        log.info("Using cached dataset: %s", cache_path)
        return cache_path.read_text(encoding="utf-8", errors="replace")
    log.info("Downloading %s", url)
    try:
        with urlopen_resilient(url, timeout=120) as resp:
            text = resp.read().decode("utf-8", errors="replace")
    except URLError as exc:
        if cache_path.is_file():
            log.warning("Download failed (%s); using stale cache", exc)
            return cache_path.read_text(encoding="utf-8", errors="replace")
        raise RuntimeError(f"Failed to download dataset: {exc}") from exc
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(text, encoding="utf-8")
    return text


def split_md_cells(line: str) -> list[str]:
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    return [p.strip() for p in re.split(r"(?<!\\)\|", s)]


def normalize_payload(text: str) -> str:
    t = text.strip().lower()
    t = re.sub(r"\s+", " ", t)
    return t


def payload_digest(text: str) -> str:
    return hashlib.sha256(normalize_payload(text).encode("utf-8")).hexdigest()


def prefix_key(text: str) -> str:
    return normalize_payload(text)[:PREFIX_DEDUP_LEN]


def classify_payload(text: str) -> str:
    for category, pattern in CATEGORY_RULES:
        if pattern.search(text):
            return category
    return "LLM Prompt Injection"


def build_title(category: str, payload: str) -> str:
    preview = re.sub(r"\s+", " ", payload.strip())
    if len(preview) > 96:
        preview = preview[:93] + "..."
    return f"{category}: {preview}"


def diversity_score(payload: str) -> float:
    words = set(re.findall(r"[a-zA-Z\u00C0-\u024F]{3,}", payload.lower()))
    return min(len(payload), 400) * 0.05 + len(words) * 2.0


def similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, normalize_payload(a), normalize_payload(b)).ratio()


def parse_csv_rows(csv_text: str) -> list[str]:
    reader = csv.DictReader(io.StringIO(csv_text))
    field = "prompt_injections"
    if reader.fieldnames and field not in reader.fieldnames:
        field = reader.fieldnames[0]
    payloads: list[str] = []
    for row in reader:
        raw = (row.get(field) or "").strip()
        if raw and len(raw) >= 12:
            payloads.append(raw)
    log.info("Parsed %d prompt injection rows from CSV", len(payloads))
    return payloads


def load_pattern_index(patterns_path: Path) -> PatternIndex:
    idx = PatternIndex()
    if not patterns_path.is_file():
        return idx
    for raw in patterns_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not raw.strip().startswith("|"):
            continue
        cols = split_md_cells(raw)
        if len(cols) < 3:
            continue
        mid = cols[0].strip("` ").upper()
        m = LLM_INJ_ID_RE.match(mid)
        if m:
            idx.metric_ids.add(mid)
            idx.max_llm_inj_num = max(idx.max_llm_inj_num, int(m.group(1)))
        if SOURCE_LABEL in (cols[5] if len(cols) > 5 else ""):
            anti = re.sub(r"`+", "", cols[2].replace("<br>", "\n"))
            if anti.strip():
                idx.payload_hashes.add(payload_digest(anti))
                idx.prefix_keys.add(prefix_key(anti))
    return idx


def is_known_duplicate(idx: PatternIndex, payload: str) -> bool:
    digest = payload_digest(payload)
    if digest in idx.payload_hashes:
        return True
    pfx = prefix_key(payload)
    if pfx in idx.prefix_keys:
        return True
    return False


def is_similar_to_selected(payload: str, selected_payloads: list[str]) -> bool:
    for other in selected_payloads:
        if similarity(payload, other) >= SIMILARITY_THRESHOLD:
            return True
        if prefix_key(payload) == prefix_key(other):
            return True
    return False


def select_representative_payloads(
    payloads: Iterable[str],
    *,
    limit: int,
    idx: PatternIndex,
) -> list[tuple[str, str]]:
    """Return (payload, category) tuples — diverse, deduplicated candidates."""
    limit = max(MIN_SELECT_COUNT, min(limit, MAX_SELECT_COUNT))
    seen_hashes: set[str] = set(idx.payload_hashes)
    seen_prefixes: set[str] = set(idx.prefix_keys)
    buckets: dict[str, list[tuple[str, str, float]]] = defaultdict(list)

    for payload in payloads:
        digest = payload_digest(payload)
        pfx = prefix_key(payload)
        if digest in seen_hashes or pfx in seen_prefixes:
            continue
        seen_hashes.add(digest)
        seen_prefixes.add(pfx)
        category = classify_payload(payload)
        buckets[category].append((payload, category, diversity_score(payload)))

    for category in buckets:
        buckets[category].sort(key=lambda x: x[2], reverse=True)

    categories = sorted(buckets.keys(), key=lambda c: (-len(buckets[c]), c))
    selected: list[tuple[str, str]] = []
    selected_payloads: list[str] = []

    while len(selected) < limit and categories:
        progressed = False
        for category in list(categories):
            if len(selected) >= limit:
                break
            pool = buckets.get(category, [])
            while pool:
                payload, cat, _score = pool.pop(0)
                if is_similar_to_selected(payload, selected_payloads):
                    continue
                selected.append((payload, cat))
                selected_payloads.append(payload)
                progressed = True
                break
            if not buckets[category]:
                categories.remove(category)
        if not progressed:
            break

    log.info(
        "Selected %d representative vectors across %d categories",
        len(selected),
        len({c for _, c in selected}),
    )
    return selected


def allocate_metric_id(idx: PatternIndex) -> str:
    idx.max_llm_inj_num += 1
    return f"LLM-INJ-{idx.max_llm_inj_num:03d}"


def payload_to_lines(payload: str) -> list[str]:
    text = payload.strip()
    if len(text) > MAX_ANTI_CHARS:
        text = text[: MAX_ANTI_CHARS - 3] + "..."
    lines = text.splitlines() or [text]
    if len(lines) > MAX_ANTI_LINES:
        lines = lines[: MAX_ANTI_LINES - 1] + ["..."]
    return lines


def lines_to_md_cell(lines: list[str]) -> str:
    if not lines:
        return "`N/A`"
    escaped = [ln.replace("|", "\\|").replace("`", "'") for ln in lines]
    return "<br>".join(f"`{ln}`" for ln in escaped)


def build_semantic_anchor(metric_id: str, title: str, payload: str) -> str:
    blob = " ".join([metric_id.lower(), title.lower(), payload[:200].lower()])
    tokens: list[str] = []
    seen: set[str] = set()
    for t in re.findall(r"[a-z0-9\u00C0-\u024F]{2,}", blob):
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


def extract_patterns(csv_text: str, idx: PatternIndex, *, select_limit: int) -> list[LlmInjectionPattern]:
    payloads = parse_csv_rows(csv_text)
    chosen = select_representative_payloads(payloads, limit=select_limit, idx=idx)
    patterns: list[LlmInjectionPattern] = []
    for payload, category in chosen:
        if is_known_duplicate(idx, payload):
            continue
        metric_id = allocate_metric_id(idx)
        patterns.append(
            LlmInjectionPattern(
                metric_id=metric_id,
                category=category,
                title=build_title(category, payload),
                payload=payload,
                payload_hash=payload_digest(payload),
            )
        )
    return patterns


def write_patterns(
    items: Iterable[LlmInjectionPattern],
    *,
    dry_run: bool,
) -> int:
    patterns_path = SKILLS_DIR / SKILL_DIR / "patterns.md"
    idx = load_pattern_index(patterns_path)
    rows: list[str] = []
    imported = 0

    for item in items:
        if item.metric_id.upper() in idx.metric_ids or item.payload_hash in idx.payload_hashes:
            log.info("SKIP %s: already present", item.metric_id)
            continue

        anti_cell = lines_to_md_cell(payload_to_lines(item.payload))
        safe_cell = lines_to_md_cell([SAFE_PLACEHOLDER])
        anchor = build_semantic_anchor(item.metric_id, item.title, item.payload)
        row = format_table_row(
            item.metric_id,
            item.title,
            anti_cell,
            safe_cell,
            SOURCE_LABEL,
            DEFAULT_FIX,
            DEFAULT_EXPLOIT,
            anchor,
        )

        if dry_run:
            log.info("DRY-RUN %s [%s] %s", item.metric_id, item.category, item.title[:72])
        else:
            rows.append(row)
            log.info("IMPORTED %s -> %s (%s)", item.metric_id, SKILL_DIR, item.category)
        imported += 1

    if not dry_run and rows:
        append_pattern_rows(patterns_path, rows)

    log.info("Write summary: imported=%d", imported)
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
        description="Import HuggingFace prompt_injections vectors into HexVibe patterns.md",
    )
    p.add_argument("--url", default=HF_CSV_URL, help="Raw CSV URL on HuggingFace")
    p.add_argument("--cache-file", type=Path, default=CACHE_CSV, help="Local CSV cache path")
    p.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_SELECT_COUNT,
        help=f"Max unique vectors to import ({MIN_SELECT_COUNT}-{MAX_SELECT_COUNT}, default {DEFAULT_SELECT_COUNT})",
    )
    p.add_argument("--dry-run", action="store_true", help="Parse and log only; do not write files")
    p.add_argument("--skip-sync", action="store_true", help="Do not run scripts/sync_semgrep.py")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logging(args.verbose)
    select_limit = max(MIN_SELECT_COUNT, min(args.limit, MAX_SELECT_COUNT))

    log.info(
        "HexVibe LLM injection ingest (skill=%s, stack=%s, select=%d)",
        SKILL_DIR,
        STACK,
        select_limit,
    )
    try:
        patterns_path = SKILLS_DIR / SKILL_DIR / "patterns.md"
        idx = load_pattern_index(patterns_path)
        csv_text = fetch_dataset_csv(args.url, args.cache_file)
        candidates = extract_patterns(csv_text, idx, select_limit=select_limit)
        imported = write_patterns(candidates, dry_run=args.dry_run)
        if imported and not args.dry_run:
            run_post_pipeline(args.skip_sync)
        elif imported == 0:
            log.info("No new LLM injection patterns imported")
        else:
            log.info("Dry-run complete (%d would import)", imported)
        log.info("Done. New patterns: %d / selected: %d", imported, len(candidates))
        return 0
    except Exception:
        log.exception("LLM injection ingest failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
