#!/usr/bin/env python3
"""
ETL: import scanner ground-truth test pairs into HexVibe ``core/skills/*/patterns.md``.

Sources:
  - Checkov  (bridgecrewio/checkov)  — tests/kubernetes, tests/dockerfile
  - KICS     (Checkmarx/kics)        — assets/queries/k8s, assets/queries/dockerfile
  - Semgrep  (semgrep/semgrep-rules) — rule *.yaml + sibling test sources

Usage (repo root):
  python scripts/ingest_scanner_tests.py
  python scripts/ingest_scanner_tests.py --target checkov --dry-run
  python scripts/ingest_scanner_tests.py --checkov-repo /path/to/checkov --skip-sync
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
import textwrap
import zipfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path
from typing import Iterable, Iterator
from urllib.error import URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
SKILLS_DIR = ROOT / "core" / "skills"
CACHE_DIR = ROOT / ".cache" / "scanner-tests"

CHECKOV_REPO_URL = "https://github.com/bridgecrewio/checkov.git"
KICS_REPO_URL = "https://github.com/Checkmarx/kics.git"
SEMGREP_REPO_URL = "https://github.com/semgrep/semgrep-rules.git"

CHECKOV_ZIP = "https://github.com/bridgecrewio/checkov/archive/refs/heads/main.zip"
KICS_ZIP = "https://github.com/Checkmarx/kics/archive/refs/heads/master.zip"
SEMGREP_ZIP = "https://github.com/semgrep/semgrep-rules/archive/refs/heads/develop.zip"

METRIC_ID_RE = re.compile(r"^[A-Z0-9]{2,8}-[0-9A-Za-z][0-9A-Za-z.\-]*$")
CKV_ID_RE = re.compile(r"CKV_(?:K8S|DOCKER|K3S|K3D|HELM)_[0-9]+", re.I)
CWE_RE = re.compile(r"CWE-(\d+)", re.I)

DEFAULT_EXPLOIT = (
    "Атакующий доставляет входные данные, соответствующие anti-pattern; "
    "реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия."
)
DEFAULT_FIX = (
    "Autofix: apply scanner-recommended remediation, secure defaults, "
    "and policy-as-code guardrails."
)

MAX_CODE_LINES = 12
SIMILARITY_THRESHOLD = 0.72

RULEID_MARKER = re.compile(
    r"^\s*(?:#|//)\s*ruleid:\s*(?P<id>\S+)\s*$",
    re.I | re.M,
)
OK_MARKER = re.compile(
    r"^\s*(?:#|//)\s*ok\b\s*:?\s*(?P<label>\S*)?\s*$",
    re.I | re.M,
)

log = logging.getLogger("ingest_scanner_tests")


@dataclass(frozen=True)
class DomainTarget:
    skill_dir: str
    id_prefix: str
    stack: str


K8S_TARGET = DomainTarget("infra-k8s-helm", "INF", "Kubernetes/Infra")
DOCKER_TARGET = DomainTarget("devops-security", "DVS", "DevOps/Supply Chain")

SEMGREP_LANG_TARGETS: dict[str, DomainTarget] = {
    "python": DomainTarget("fastapi-async", "FAS", "Python/FastAPI"),
    "java": DomainTarget("java-spring", "JAVA", "Java/Spring"),
    "javascript": DomainTarget("nodejs-nestjs", "NST", "Node.js/NestJS"),
    "typescript": DomainTarget("nodejs-nestjs", "NST", "Node.js/NestJS"),
    "go": DomainTarget("go-core", "GO", "Go"),
    "ruby": DomainTarget("ruby-rails", "RUB", "Ruby/Rails"),
    "csharp": DomainTarget("csharp-dotnet", "CSH", ".NET/C#"),
    "php": DomainTarget("php-security", "PHP", "PHP"),
    "rust": DomainTarget("rust-security", "RST", "Rust"),
    "yaml": DomainTarget("infra-k8s-helm", "INF", "Kubernetes/Infra"),
    "dockerfile": DomainTarget("devops-security", "DVS", "DevOps/Supply Chain"),
    "generic": DomainTarget("devops-security", "DVS", "DevOps/Supply Chain"),
}


@dataclass
class ScannerPattern:
    check_id: str
    title: str
    anti_lines: list[str]
    safe_lines: list[str]
    target: DomainTarget
    source: str
    scanner: str


@dataclass
class PatternIndex:
    check_ids: set[str] = field(default_factory=set)
    anti_fingerprints: list[tuple[str, set[str]]] = field(default_factory=list)
    max_ids: dict[str, int] = field(default_factory=dict)


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
    skip = {"apiversion", "kind", "metadata", "spec", "name", "true", "false", "from", "run"}
    return {t for t in tokens if t not in skip}


def similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()


def load_pattern_index(patterns_path: Path, id_prefix: str) -> PatternIndex:
    idx = PatternIndex()
    if not patterns_path.is_file():
        return idx
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
        for token in re.findall(r"[A-Za-z0-9][A-Za-z0-9_\-./]{2,}", source):
            idx.check_ids.add(token.upper())
        anti = cols[2] if len(cols) > 2 else ""
        anti_plain = re.sub(r"<br>", "\n", anti)
        anti_plain = re.sub(r"`+", "", anti_plain)
        idx.anti_fingerprints.append((mid, normalize_fingerprint(anti_plain)))
        m = re.match(rf"{re.escape(id_prefix)}-(\d+)", mid, re.I)
        if m:
            idx.max_ids[id_prefix] = max(idx.max_ids.get(id_prefix, 0), int(m.group(1)))
    return idx


def is_duplicate(idx: PatternIndex, check_id: str, anti_lines: list[str]) -> tuple[bool, str]:
    cid = check_id.upper()
    if cid in idx.check_ids:
        return True, f"check id {check_id} already present"
    anti_fp = normalize_fingerprint("\n".join(anti_lines))
    anti_joined = "\n".join(anti_lines)
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


def trim_lines(lines: list[str], limit: int = MAX_CODE_LINES) -> list[str]:
    cleaned = [ln.rstrip() for ln in lines if ln.strip()]
    if len(cleaned) <= limit:
        return cleaned
    head = cleaned[: max(3, limit - 2)]
    tail = cleaned[-2:]
    return head + ["..."] + tail


def read_text_lines(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log.debug("read failed %s: %s", path, exc)
        return []
    return trim_lines(text.splitlines())


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


def next_metric_id(idx: PatternIndex, prefix: str) -> str:
    n = idx.max_ids.get(prefix, 0) + 1
    idx.max_ids[prefix] = n
    return f"{prefix}-{n:03d}"


class BaseExtractor(ABC):
    scanner_name: str = "scanner"

    def __init__(self, repo: Path) -> None:
        self.repo = repo

    @abstractmethod
    def extract(self) -> list[ScannerPattern]:
        ...

    def _log_skip(self, check_id: str, reason: str) -> None:
        log.info("SKIP %s: %s", check_id, reason)


class CheckovExtractor(BaseExtractor):
    scanner_name = "checkov"

    SCAN_ROOTS = (
        ("tests/kubernetes", "kubernetes"),
        ("tests/dockerfile", "docker"),
    )

    def extract(self) -> list[ScannerPattern]:
        patterns: list[ScannerPattern] = []
        seen: set[str] = set()
        for rel_root, domain_key in self.SCAN_ROOTS:
            root = self.repo / rel_root
            if not root.is_dir():
                log.warning("Checkov path missing: %s", root)
                continue
            log.info("Scanning Checkov %s (%s)", rel_root, domain_key)
            for item in self._iter_checkov_cases(root, domain_key):
                if item.check_id in seen:
                    continue
                seen.add(item.check_id)
                patterns.append(item)
        log.info("Checkov extracted %d unique patterns", len(patterns))
        return patterns

    def _iter_checkov_cases(self, root: Path, domain_key: str) -> Iterator[ScannerPattern]:
        # 1) Explicit pass/fail pairs in the same directory (user-specified layout).
        for directory in sorted(root.rglob("*")):
            if not directory.is_dir():
                continue
            pair = self._pair_from_pass_fail_files(directory, domain_key)
            if pair:
                yield pair

        # 2) example_* fixture directories (actual Checkov upstream layout).
        checks_dir = root / "checks"
        if checks_dir.is_dir():
            for example_dir in sorted(checks_dir.glob("example_*")):
                if not example_dir.is_dir():
                    continue
                pair = self._pair_from_example_dir(example_dir, domain_key, checks_dir)
                if pair:
                    yield pair

    def _domain_for_check(self, check_id: str, domain_key: str) -> DomainTarget:
        if "DOCKER" in check_id.upper() or domain_key == "docker":
            return DOCKER_TARGET
        return K8S_TARGET

    def _pair_from_pass_fail_files(self, directory: Path, domain_key: str) -> ScannerPattern | None:
        fail_yaml = directory / "fail.yaml"
        pass_yaml = directory / "pass.yaml"
        fail_docker = directory / "fail.Dockerfile"
        pass_docker = directory / "pass.Dockerfile"

        anti: list[str] = []
        safe: list[str] = []
        if fail_yaml.is_file() and pass_yaml.is_file():
            anti, safe = read_text_lines(fail_yaml), read_text_lines(pass_yaml)
        elif fail_docker.is_file() and pass_docker.is_file():
            anti, safe = read_text_lines(fail_docker), read_text_lines(pass_docker)
        else:
            return None
        if not anti or not safe:
            return None

        check_id = self._resolve_check_id(directory, domain_key)
        if not check_id:
            return None
        target = self._domain_for_check(check_id, domain_key)
        title = self._title_for_checkov(check_id, directory)
        source = f"Checkov {check_id}"
        return ScannerPattern(check_id, title, anti, safe, target, source, self.scanner_name)

    def _pair_from_example_dir(
        self,
        example_dir: Path,
        domain_key: str,
        checks_dir: Path,
    ) -> ScannerPattern | None:
        anti = self._first_matching_file(
            example_dir,
            ("*-FAILED.yaml", "*-FAILED.yml", "fail.yaml", "failure/**/Dockerfile", "failure/**/*.yaml"),
        )
        safe = self._first_matching_file(
            example_dir,
            ("*-PASSED.yaml", "*-PASSED.yml", "pass.yaml", "success/**/Dockerfile", "success/**/*.yaml"),
        )
        if not anti or not safe:
            return None
        anti_lines, safe_lines = read_text_lines(anti), read_text_lines(safe)
        if not anti_lines or not safe_lines:
            return None

        check_id = self._resolve_check_id(example_dir, domain_key, checks_dir)
        if not check_id:
            return None
        target = self._domain_for_check(check_id, domain_key)
        title = self._title_for_checkov(check_id, example_dir)
        source = f"Checkov {check_id}"
        return ScannerPattern(check_id, title, anti_lines, safe_lines, target, source, self.scanner_name)

    def _first_matching_file(self, base: Path, patterns: tuple[str, ...]) -> Path | None:
        for pat in patterns:
            if "**" in pat:
                hits = sorted(base.glob(pat))
            else:
                hits = sorted(base.glob(pat))
            for hit in hits:
                if hit.is_file():
                    return hit
        return None

    def _resolve_check_id(
        self,
        case_dir: Path,
        domain_key: str,
        checks_dir: Path | None = None,
    ) -> str | None:
        for part in case_dir.parts:
            m = CKV_ID_RE.search(part)
            if m:
                return m.group(0).upper()

        name = case_dir.name
        if name.startswith("example_"):
            example_suffix = name[len("example_") :]
            test_py = None
            search_root = checks_dir or case_dir.parent
            for candidate in search_root.glob(f"test_{example_suffix}.py"):
                test_py = candidate
                break
            if test_py is None:
                for candidate in search_root.glob(f"test_*{example_suffix}*.py"):
                    test_py = candidate
                    break
            if test_py and test_py.is_file():
                cid = self._check_id_from_test_py(test_py)
                if cid:
                    return cid

        # Walk up and inspect sibling test files.
        for test_py in case_dir.parent.glob("test_*.py"):
            cid = self._check_id_from_test_py(test_py)
            if cid:
                return cid

        log.debug("Could not resolve Checkov ID for %s (%s)", case_dir, domain_key)
        return None

    def _check_id_from_test_py(self, test_py: Path) -> str | None:
        try:
            text = test_py.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        m = re.search(
            r"from\s+(checkov\.[\w.]+)\s+import\s+check\b",
            text,
        )
        if not m:
            m = re.search(r'checks\s*=\s*\[\s*["\'](CKV_[^"\']+)["\']\s*\]', text)
            if m:
                return m.group(1).upper()
            return None
        module_path = m.group(1).replace(".", "/") + ".py"
        check_file = self.repo / module_path
        if not check_file.is_file():
            return None
        try:
            src = check_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        id_m = re.search(r'\bid\s*=\s*["\'](CKV_[^"\']+)["\']', src)
        return id_m.group(1).upper() if id_m else None

    def _title_for_checkov(self, check_id: str, case_dir: Path) -> str:
        name = case_dir.name.replace("example_", "").replace("_", " ").strip()
        domain = "Docker" if "DOCKER" in check_id else "Kubernetes"
        if name and name.lower() not in check_id.lower():
            return f"Checkov {domain}: {name} ({check_id})"
        return f"Checkov {domain}: {check_id}"


class KicsExtractor(BaseExtractor):
    scanner_name = "kics"

    QUERY_ROOTS = (
        ("assets/queries/k8s", K8S_TARGET),
        ("assets/queries/dockerfile", DOCKER_TARGET),
    )

    def extract(self) -> list[ScannerPattern]:
        patterns: list[ScannerPattern] = []
        seen: set[str] = set()
        for rel_root, target in self.QUERY_ROOTS:
            root = self.repo / rel_root
            if not root.is_dir():
                log.warning("KICS path missing: %s", root)
                continue
            log.info("Scanning KICS %s", rel_root)
            for query_dir in sorted(p for p in root.iterdir() if p.is_dir()):
                item = self._pair_from_query_dir(query_dir, target)
                if not item or item.check_id in seen:
                    continue
                seen.add(item.check_id)
                patterns.append(item)
        log.info("KICS extracted %d unique patterns", len(patterns))
        return patterns

    def _pair_from_query_dir(self, query_dir: Path, target: DomainTarget) -> ScannerPattern | None:
        meta_path = query_dir / "metadata.json"
        positive = query_dir / "test" / "positive.yaml"
        negative = query_dir / "test" / "negative.yaml"
        if not meta_path.is_file():
            log.debug("KICS skip (no metadata): %s", query_dir.name)
            return None
        if not positive.is_file() or not negative.is_file():
            log.debug("KICS skip (missing test pair): %s", query_dir.name)
            return None
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            log.debug("KICS metadata parse error %s: %s", query_dir.name, exc)
            return None

        anti_lines = read_text_lines(positive)
        safe_lines = read_text_lines(negative)
        if not anti_lines or not safe_lines:
            return None

        query_name = str(meta.get("queryName") or query_dir.name).strip()
        check_id = f"KICS_{query_dir.name.upper()}"
        cwe = meta.get("cwe")
        cwe_suffix = f" CWE-{cwe}" if cwe else ""
        title = f"KICS: {query_name}{cwe_suffix}"
        source = f"KICS {query_name} ({query_dir.name})"
        return ScannerPattern(check_id, title, anti_lines, safe_lines, target, source, self.scanner_name)


class SemgrepExtractor(BaseExtractor):
    scanner_name = "semgrep"

    TEST_EXTENSIONS = (".py", ".js", ".ts", ".tsx", ".java", ".go", ".rb", ".php", ".cs", ".yaml", ".yml")

    def extract(self) -> list[ScannerPattern]:
        patterns: list[ScannerPattern] = []
        seen: set[str] = set()
        log.info("Scanning Semgrep rules under %s", self.repo)
        for rule_yaml in sorted(self.repo.rglob("*.yaml")):
            if ".github" in rule_yaml.parts:
                continue
            if not self._looks_like_rule_file(rule_yaml):
                continue
            for item in self._patterns_from_rule(rule_yaml):
                if item.check_id in seen:
                    continue
                seen.add(item.check_id)
                patterns.append(item)
        log.info("Semgrep extracted %d unique patterns", len(patterns))
        return patterns

    def _looks_like_rule_file(self, path: Path) -> bool:
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:4096]
        except OSError:
            return False
        return "rules:" in head and "id:" in head

    def _patterns_from_rule(self, rule_yaml: Path) -> list[ScannerPattern]:
        out: list[ScannerPattern] = []
        rule_ids = self._rule_ids_from_yaml(rule_yaml)
        if not rule_ids:
            return out
        test_file = self._find_test_file(rule_yaml)
        if not test_file:
            log.debug("Semgrep: no test file for %s", rule_yaml)
            return out

        try:
            test_src = test_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return out

        blocks = self._extract_ruleid_ok_blocks(test_src)
        meta = self._yaml_rule_meta(rule_yaml)

        for rule_id in rule_ids:
            block = blocks.get(rule_id)
            if not block:
                continue
            anti_lines, safe_lines = block
            if not anti_lines or not safe_lines:
                continue
            target = self._target_for_semgrep(rule_yaml, meta)
            title = f"Semgrep: {meta.get('message') or rule_id}"
            if len(title) > 120:
                title = title[:117] + "..."
            check_id = f"SEMGREP_{rule_id.upper()}"
            source = f"Semgrep {rule_id}"
            out.append(
                ScannerPattern(check_id, title, anti_lines, safe_lines, target, source, self.scanner_name)
            )
        return out

    def _rule_ids_from_yaml(self, rule_yaml: Path) -> list[str]:
        try:
            text = rule_yaml.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        return [m.group(1) for m in re.finditer(r"^\s*-\s*id:\s*(\S+)\s*$", text, re.M)]

    def _yaml_rule_meta(self, rule_yaml: Path) -> dict[str, str]:
        meta: dict[str, str] = {}
        try:
            text = rule_yaml.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return meta
        msg = re.search(r"^\s*message:\s*(.+)$", text, re.M)
        if msg:
            meta["message"] = msg.group(1).strip().strip("'\"")
        langs = re.search(r"^\s*languages:\s*\[(.+)\]\s*$", text, re.M)
        if langs:
            meta["languages"] = langs.group(1)
        tech = re.search(r"^\s*-\s*(\w+)\s*$", text.split("technology:")[-1][:200] if "technology:" in text else "")
        if tech:
            meta["technology"] = tech.group(1)
        return meta

    def _find_test_file(self, rule_yaml: Path) -> Path | None:
        stem = rule_yaml.stem
        parent = rule_yaml.parent
        for ext in self.TEST_EXTENSIONS:
            candidate = parent / f"{stem}{ext}"
            if candidate.is_file() and candidate != rule_yaml:
                return candidate
        for ext in self.TEST_EXTENSIONS:
            for candidate in parent.glob(f"*{ext}"):
                if candidate.is_file() and candidate.suffix == ext:
                    return candidate
        return None

    def _extract_ruleid_ok_blocks(self, source: str) -> dict[str, tuple[list[str], list[str]]]:
        """Map rule id -> (anti lines, safe lines) from ruleid/ok comment markers."""
        result: dict[str, tuple[list[str], list[str]]] = {}
        lines = source.splitlines()
        i = 0
        while i < len(lines):
            m = RULEID_MARKER.match(lines[i])
            if not m:
                i += 1
                continue
            rule_id = m.group("id")
            i += 1
            anti: list[str] = []
            while i < len(lines):
                if RULEID_MARKER.match(lines[i]) or OK_MARKER.match(lines[i]):
                    break
                if lines[i].strip():
                    anti.append(lines[i].rstrip())
                i += 1
            safe: list[str] = []
            if i < len(lines) and OK_MARKER.match(lines[i]):
                i += 1
                while i < len(lines):
                    if RULEID_MARKER.match(lines[i]) or OK_MARKER.match(lines[i]):
                        break
                    if lines[i].strip():
                        safe.append(lines[i].rstrip())
                    i += 1
            if anti:
                result[rule_id] = (trim_lines(anti), trim_lines(safe))
        return result

    def _target_for_semgrep(self, rule_yaml: Path, meta: dict[str, str]) -> DomainTarget:
        lang_blob = (meta.get("languages") or "") + " " + (meta.get("technology") or "")
        lang_blob += " " + rule_yaml.as_posix()
        lang_blob = lang_blob.lower()
        for lang, target in SEMGREP_LANG_TARGETS.items():
            if lang in lang_blob:
                return target
        return SEMGREP_LANG_TARGETS["generic"]


EXTRACTORS: dict[str, type[BaseExtractor]] = {
    "checkov": CheckovExtractor,
    "kics": KicsExtractor,
    "semgrep": SemgrepExtractor,
}


def write_patterns(
    items: Iterable[ScannerPattern],
    *,
    dry_run: bool,
    limit: int | None,
) -> int:
    indices: dict[str, PatternIndex] = {}
    imported = 0

    for item in items:
        if limit is not None and imported >= limit:
            break
        patterns_path = SKILLS_DIR / item.target.skill_dir / "patterns.md"
        prefix = item.target.id_prefix
        if prefix not in indices:
            indices[prefix] = load_pattern_index(patterns_path, prefix)

        idx = indices[prefix]
        dup, reason = is_duplicate(idx, item.check_id, item.anti_lines)
        if dup:
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
        fix_template = lines_to_fix_template(item.safe_lines)
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
            log.info(
                "DRY-RUN import %s -> %s [%s] scanner=%s",
                item.check_id,
                metric_id,
                item.target.skill_dir,
                item.scanner,
            )
        else:
            append_pattern_row(patterns_path, row)
            idx.check_ids.add(item.check_id.upper())
            idx.anti_fingerprints.append(
                (metric_id, normalize_fingerprint("\n".join(item.anti_lines)))
            )
            log.info(
                "IMPORTED %s -> %s (%s) scanner=%s",
                item.check_id,
                metric_id,
                item.target.skill_dir,
                item.scanner,
            )
        imported += 1

    return imported


def run_post_pipeline(skip_sync: bool) -> None:
    if skip_sync:
        log.info("Skipping post-pipeline (--skip-sync)")
        return
    for script in ("scripts/sync_semgrep.py", "scripts/render_skill_indexes.py"):
        log.info("Running %s ...", script)
        proc = run_cmd([sys.executable, script])
        if proc.returncode != 0:
            log.error("%s failed:\n%s", script, proc.stderr.strip())
            raise RuntimeError(f"Post-pipeline failed: {script}")
        log.info("%s completed OK", script)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Import scanner test pairs into HexVibe patterns.md")
    p.add_argument(
        "--target",
        choices=tuple(EXTRACTORS.keys()) + ("all",),
        default="all",
        help="Scanner source to ingest (default: all)",
    )
    p.add_argument("--checkov-repo", type=Path, default=None)
    p.add_argument("--kics-repo", type=Path, default=None)
    p.add_argument("--semgrep-repo", type=Path, default=None)
    p.add_argument("--cache-dir", type=Path, default=CACHE_DIR)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--skip-sync", action="store_true")
    p.add_argument("--limit", type=int, default=None, help="Max new patterns to import")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logging(args.verbose)
    global CACHE_DIR
    CACHE_DIR = args.cache_dir.resolve()

    log.info("HexVibe scanner-test ingest (root=%s)", ROOT)
    targets = list(EXTRACTORS.keys()) if args.target == "all" else [args.target]
    all_patterns: list[ScannerPattern] = []

    try:
        if "checkov" in targets:
            repo = resolve_repo(args.checkov_repo, CHECKOV_REPO_URL, "checkov", CHECKOV_ZIP)
            all_patterns.extend(CheckovExtractor(repo).extract())
        if "kics" in targets:
            repo = resolve_repo(args.kics_repo, KICS_REPO_URL, "kics", KICS_ZIP)
            all_patterns.extend(KicsExtractor(repo).extract())
        if "semgrep" in targets:
            repo = resolve_repo(args.semgrep_repo, SEMGREP_REPO_URL, "semgrep-rules", SEMGREP_ZIP)
            all_patterns.extend(SemgrepExtractor(repo).extract())

        imported = write_patterns(all_patterns, dry_run=args.dry_run, limit=args.limit)
        if imported and not args.dry_run:
            run_post_pipeline(args.skip_sync)
        elif imported == 0:
            log.info("No new patterns imported")
        else:
            log.info("Dry-run complete (%d would import)", imported)

        log.info("Done. New patterns: %d / candidates: %d", imported, len(all_patterns))
        return 0
    except Exception:
        log.exception("Scanner ingest failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
