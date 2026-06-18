#!/usr/bin/env python3
"""
ETL: import AWS managed IAM policy least-privilege violations into HexVibe ``patterns.md``.

Source: https://github.com/iann0036/iam-dataset (``aws/managedpolicies/*.json``).

Flags over-permissive ``Allow`` statements where ``Action`` or ``Resource`` is ``*``.

Usage (repo root):
  python scripts/ingest_iam_policies.py
  python scripts/ingest_iam_policies.py --dry-run --limit 20
  python scripts/ingest_iam_policies.py --repo /path/to/iam-dataset --skip-sync
"""
from __future__ import annotations

import argparse
import io
import json
import logging
import re
import shutil
import subprocess
import sys
import zipfile
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Iterable
from urllib.error import URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
SKILLS_DIR = ROOT / "core" / "skills"
CACHE_DIR = ROOT / ".cache" / "iam-dataset"

IAM_REPO_URL = "https://github.com/iann0036/iam-dataset.git"
IAM_ZIP_URL = "https://github.com/iann0036/iam-dataset/archive/refs/heads/master.zip"

SKILL_DIR = "cloud-secrets"
STACK = "aws/iam"
SOURCE_LABEL = "iam-dataset"
SAFE_PLACEHOLDER = "TODO: AI Generate Least Privilege Policy"

IAM_METRIC_ID_RE = re.compile(r"^IAM-AWS-[A-Za-z0-9][A-Za-z0-9_-]*$")
METRIC_ID_RE = re.compile(r"^[A-Z0-9]{2,8}-[0-9A-Za-z][0-9A-Za-z.\-]*$")

SIMILARITY_THRESHOLD = 0.72
MAX_JSON_LINES = 10
MAX_SIMILARITY_FINGERPRINTS = 200

DEFAULT_EXPLOIT = (
    "Принципу с наименьшими привилегиями присвоена избыточная IAM-политика; "
    "компрометация субъекта (роль/пользователь) ведёт к lateral movement и эскалации в AWS."
)
DEFAULT_FIX = (
    "Autofix: заменить wildcard Action/Resource на явный allowlist; "
    "разделить политики по сервисам, добавить Condition и permissions boundary."
)

log = logging.getLogger("ingest_iam_policies")


@dataclass(frozen=True)
class IamPolicyPattern:
    metric_id: str
    policy_name: str
    title: str
    anti_lines: list[str]
    source: str


@dataclass
class PatternIndex:
    metric_ids: set[str] = field(default_factory=set)
    policy_names: set[str] = field(default_factory=set)
    anti_fingerprints: list[tuple[str, set[str]]] = field(default_factory=list)


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


def resolve_repo(path: Path | None) -> Path:
    if path is not None:
        p = path.resolve()
        if not p.is_dir():
            raise FileNotFoundError(f"Local iam-dataset repo not found: {p}")
        log.info("Using local repo: %s", p)
        return p
    dest = CACHE_DIR
    clone_or_update_repo(IAM_REPO_URL, dest, IAM_ZIP_URL)
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
    skip = {"effect", "allow", "action", "resource", "version", "statement", "true", "false"}
    return {t for t in tokens if t not in skip}


def similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()


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
        if IAM_METRIC_ID_RE.match(mid):
            idx.metric_ids.add(mid.upper())
            name = mid[len("IAM-AWS-") :]
            idx.policy_names.add(name.upper())
        source_idx = 5 if len(cols) >= 6 else 4
        source = cols[source_idx] if source_idx < len(cols) else ""
        if SOURCE_LABEL in source.lower():
            m = re.search(r"IAM-AWS-([A-Za-z0-9][A-Za-z0-9_-]*)", source, re.I)
            if m:
                idx.policy_names.add(m.group(1).upper())
        anti = cols[2] if len(cols) > 2 else ""
        anti_plain = re.sub(r"<br>", "\n", anti)
        anti_plain = re.sub(r"`+", "", anti_plain)
        if IAM_METRIC_ID_RE.match(mid):
            idx.anti_fingerprints.append((mid, normalize_fingerprint(anti_plain)))
    return idx


def is_duplicate(idx: PatternIndex, pattern: IamPolicyPattern) -> tuple[bool, str]:
    mid = pattern.metric_id.upper()
    pname = pattern.policy_name.upper()
    if mid in idx.metric_ids or pname in idx.policy_names:
        return True, f"policy {pattern.policy_name} already present"
    anti_fp = normalize_fingerprint("\n".join(pattern.anti_lines))
    anti_joined = "\n".join(pattern.anti_lines)
    recent = idx.anti_fingerprints[-MAX_SIMILARITY_FINGERPRINTS:]
    for _existing_id, existing_fp in recent:
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


def _is_wildcard(value: Any) -> bool:
    if value == "*":
        return True
    if isinstance(value, list):
        return any(item == "*" for item in value)
    return False


def _normalize_statements(document: dict[str, Any]) -> list[dict[str, Any]]:
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        return [statements]
    if isinstance(statements, list):
        return [s for s in statements if isinstance(s, dict)]
    return []


def find_excessive_allow_statements(document: dict[str, Any]) -> list[dict[str, Any]]:
    excessive: list[dict[str, Any]] = []
    for stmt in _normalize_statements(document):
        effect = str(stmt.get("Effect", "")).strip().lower()
        if effect != "allow":
            continue
        if _is_wildcard(stmt.get("Action")) or _is_wildcard(stmt.get("Resource")):
            excessive.append(stmt)
    return excessive


def compact_json_lines(obj: Any, limit: int = MAX_JSON_LINES) -> list[str]:
    text = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    if len(text) <= 120:
        return [text]
    pretty = json.dumps(obj, ensure_ascii=False, indent=2)
    lines = pretty.splitlines()
    if len(lines) <= limit:
        return lines
    head = lines[: max(3, limit - 2)]
    tail = lines[-2:]
    return head + ["..."] + tail


def build_policy_title(meta: dict[str, Any], policy_name: str) -> str:
    parts = [f"AWS IAM Managed Policy: {policy_name}"]
    flags: list[str] = []
    if meta.get("privesc"):
        flags.append("privilege escalation risk")
    if meta.get("resource_exposure"):
        flags.append("resource exposure")
    if meta.get("credentials_exposure"):
        flags.append("credentials exposure")
    access_levels = meta.get("access_levels")
    if isinstance(access_levels, list) and access_levels:
        flags.append("access: " + "/".join(str(x) for x in access_levels[:4]))
    if flags:
        parts.append("(" + "; ".join(flags) + ")")
    parts.append("— Least Privilege violation (wildcard Action/Resource)")
    return " ".join(parts)


def build_metric_id(policy_name: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_-]", "", policy_name)
    if not safe:
        safe = "UnknownPolicy"
    return f"IAM-AWS-{safe}"


def extract_patterns(repo: Path, *, limit: int | None = None) -> list[IamPolicyPattern]:
    policies_dir = repo / "aws" / "managedpolicies"
    if not policies_dir.is_dir():
        raise FileNotFoundError(f"Managed policies directory not found: {policies_dir}")

    patterns: list[IamPolicyPattern] = []
    files = sorted(policies_dir.glob("*.json"))
    log.info("Scanning %d managed policy JSON files in %s", len(files), policies_dir)

    for path in files:
        if limit is not None and len(patterns) >= limit:
            break
        try:
            meta = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError) as exc:
            log.debug("Skip %s: %s", path.name, exc)
            continue
        if not isinstance(meta, dict):
            continue

        policy_name = str(meta.get("name") or path.stem)
        document = meta.get("document")
        if not isinstance(document, dict):
            log.debug("Skip %s: missing policy document", policy_name)
            continue

        excessive = find_excessive_allow_statements(document)
        if not excessive:
            continue

        metric_id = build_metric_id(policy_name)
        title = build_policy_title(meta, policy_name)
        anti_lines = compact_json_lines(excessive[0] if len(excessive) == 1 else excessive)
        source = SOURCE_LABEL
        patterns.append(
            IamPolicyPattern(
                metric_id=metric_id,
                policy_name=policy_name,
                title=title,
                anti_lines=anti_lines,
                source=source,
            )
        )

    log.info("Extracted %d over-permissive managed policies", len(patterns))
    return patterns


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


def write_patterns(
    items: Iterable[IamPolicyPattern],
    *,
    dry_run: bool,
    limit: int | None = None,
) -> int:
    patterns_path = SKILLS_DIR / SKILL_DIR / "patterns.md"
    idx = load_pattern_index(patterns_path)
    pending_rows: list[str] = []
    pending_meta: list[tuple[IamPolicyPattern, str]] = []
    imported = 0
    skipped = 0

    for item in items:
        if limit is not None and imported >= limit:
            break
        dup, reason = is_duplicate(idx, item)
        if dup:
            skipped += 1
            if skipped <= 15 or skipped % 200 == 0:
                log.info("SKIP %s: %s", item.policy_name, reason)
            continue

        anti_cell = lines_to_md_cell(item.anti_lines)
        safe_cell = lines_to_md_cell([SAFE_PLACEHOLDER])
        anchor = build_semantic_anchor(item.metric_id, item.title, item.anti_lines)
        row = format_table_row(
            item.metric_id,
            item.title,
            anti_cell,
            safe_cell,
            item.source,
            DEFAULT_FIX,
            DEFAULT_EXPLOIT,
            anchor,
        )

        if dry_run:
            if imported < 15 or imported % 200 == 0:
                log.info("DRY-RUN import %s -> %s [%s]", item.policy_name, item.metric_id, SKILL_DIR)
        else:
            pending_rows.append(row)
            pending_meta.append((item, item.metric_id))
            if len(pending_rows) >= 200:
                append_pattern_rows(patterns_path, pending_rows)
                for pat, _mid in pending_meta:
                    idx.metric_ids.add(pat.metric_id.upper())
                    idx.policy_names.add(pat.policy_name.upper())
                    idx.anti_fingerprints.append(
                        (pat.metric_id, normalize_fingerprint("\n".join(pat.anti_lines)))
                    )
                pending_rows.clear()
                pending_meta.clear()
            if imported < 15 or imported % 200 == 0:
                log.info("IMPORTED %s -> %s (%s)", item.policy_name, item.metric_id, SKILL_DIR)
        imported += 1

    if not dry_run and pending_rows:
        append_pattern_rows(patterns_path, pending_rows)
        for pat, _mid in pending_meta:
            idx.metric_ids.add(pat.metric_id.upper())
            idx.policy_names.add(pat.policy_name.upper())
            idx.anti_fingerprints.append(
                (pat.metric_id, normalize_fingerprint("\n".join(pat.anti_lines)))
            )

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
        description="Import AWS IAM managed policy least-privilege violations into HexVibe patterns.md",
    )
    p.add_argument("--repo", type=Path, default=None, help="Local iam-dataset path (skip clone)")
    p.add_argument(
        "--cache-dir",
        type=Path,
        default=CACHE_DIR,
        help="Clone cache directory (default: .cache/iam-dataset)",
    )
    p.add_argument("--dry-run", action="store_true", help="Parse and log only; do not write files")
    p.add_argument("--skip-sync", action="store_true", help="Do not run scripts/sync_semgrep.py")
    p.add_argument("--limit", type=int, default=None, help="Max policies to import (debug)")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logging(args.verbose)
    global CACHE_DIR
    CACHE_DIR = args.cache_dir.resolve()

    log.info("HexVibe IAM policy ingest (skill=%s, stack=%s)", SKILL_DIR, STACK)
    try:
        repo = resolve_repo(args.repo)
        candidates = extract_patterns(repo, limit=args.limit)
        imported = write_patterns(candidates, dry_run=args.dry_run, limit=args.limit)
        if imported and not args.dry_run:
            run_post_pipeline(args.skip_sync)
        elif imported == 0:
            log.info("No new IAM patterns imported")
        else:
            log.info("Dry-run complete (%d would import)", imported)
        log.info("Done. New patterns: %d / candidates: %d", imported, len(candidates))
        return 0
    except Exception:
        log.exception("IAM policy ingest failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
