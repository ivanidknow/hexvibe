#!/usr/bin/env python3
"""
ETL: import hardcoded-secret detection rules into HexVibe ``core/skills/cloud-secrets/patterns.md``.

Sources:
  - Gitleaks   — config/gitleaks.toml (rules[].id, description, regex, keywords)
  - TruffleHog — pkg/detectors/* (Go regex patterns + *_test.go sample credentials)

Usage (repo root):
  python scripts/ingest_secrets_scanners.py
  python scripts/ingest_secrets_scanners.py --target gitleaks --dry-run
  python scripts/ingest_secrets_scanners.py --trufflehog-repo /path/to/trufflehog
"""
from __future__ import annotations

import argparse
import io
import logging
import re
import shutil
import ssl
import subprocess
import sys
import textwrap
import zipfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Iterable
from urllib.error import URLError
from urllib.request import urlopen

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

ROOT = Path(__file__).resolve().parents[1]
SKILLS_DIR = ROOT / "core" / "skills"
CACHE_DIR = ROOT / ".cache" / "secrets-scanners"

GITLEAKS_TOML_URL = "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"
TRUFFLEHOG_REPO_URL = "https://github.com/trufflesecurity/trufflehog.git"
TRUFFLEHOG_ZIP = "https://github.com/trufflesecurity/trufflehog/archive/refs/heads/main.zip"

SKILL_DIR = "cloud-secrets"
STACK = "Universal"

METRIC_ID_RE = re.compile(r"^[A-Z0-9]{2,8}(?:-[A-Z0-9]{2,4})?-[0-9A-Za-z][0-9A-Za-z.\-]*$")
SIMILARITY_THRESHOLD = 0.72

DEFAULT_EXPLOIT = (
    "Атакующий извлекает захардкоженный секрет из репозитория, CI-логов или образа; "
    "компрометация ключей ведёт к несанкционированному доступу к облаку/API (CWE-798)."
)
DEFAULT_FIX = (
    "Autofix: хранить секреты во внешнем secret manager / env injection; "
    "запретить plaintext credentials в коде и конфигурации."
)

log = logging.getLogger("ingest_secrets_scanners")

# ---------------------------------------------------------------------------
# Shared models / helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SecretRule:
    check_id: str          # e.g. SEC-GL-aws-access-key-id (logical id for dedup)
    metric_prefix: str     # SEC-GL or SEC-TH
    title: str
    anti_lines: list[str]
    safe_lines: list[str]
    source: str
    scanner: str
    provider_key: str      # normalized vendor for cross-scanner dedup


@dataclass
class PatternIndex:
    check_ids: set[str] = field(default_factory=set)
    anti_fingerprints: list[tuple[str, set[str]]] = field(default_factory=list)
    max_ids: dict[str, int] = field(default_factory=dict)


FAKE_SECRET_TEMPLATES: dict[str, str] = {
    "ghp_": "ghp_HEXVIBeFAKE0000000000000000000000",
    "gho_": "gho_HEXVIBeFAKE0000000000000000000000",
    "ghu_": "ghu_HEXVIBeFAKE0000000000000000000000",
    "ghs_": "ghs_HEXVIBeFAKE0000000000000000000000",
    "github_pat_": "github_pat_HEXVIBeFAKE0000000000000000000000",
    "xoxb-": "xoxb-HEXVIBeFAKE0000000000000000000000",
    "xoxp-": "xoxp-HEXVIBeFAKE0000000000000000000000",
    "xoxa-": "xoxa-HEXVIBeFAKE0000000000000000000000",
    "xoxr-": "xoxr-HEXVIBeFAKE0000000000000000000000",
    "akia": "AKIAHEXVIBeFAKE00000000",
    "sk-": "sk-HEXVIBeFAKE0000000000000000000000000000000000",
    "sq0atp-": "sq0atp-HEXVIBeFAKE0000000000",
    "sgp_": "sgp_HEXVIBeFAKE0000000000000000000000",
    "slk_": "slk_HEXVIBeFAKE0000000000000000000000000000000000000000000000",
    "a3-": "A3-HEXVIBeFAKE-000000-000000-00000",
    "snyk": "00000000-0000-4000-8000-HEXVIBE000001",
    "sonar": "squ_HEXVIBeFAKE0000000000000000000000",
    "slack": "xoxb-HEXVIBeFAKE0000000000000000000000",
    "stripe": "sk_test_HEXVIBeFAKE000000000000",
    "gitlab": "glpat-HEXVIBeFAKE0000000000",
    "npm_": "npm_HEXVIBeFAKE0000000000000000000000",
    "pypi-": "pypi-HEXVIBeFAKE0000000000000000000000",
    "cli_": "cli_HEXVIBeFAKE0000000000",
    "ntg": "NTgHEXVIBeFAKE0000000000000000000000000000000000",
    "ntk": "NTkHEXVIBeFAKE0000000000000000000000000000000000",
    "atlasv1": "HEXVIBeFAKE000000000000.atlasv1.HEXVIBeFAKE0000000000000000000000",
}

PROVIDER_ALIASES: tuple[tuple[str, str], ...] = (
    ("aws", "aws"),
    ("amazon", "aws"),
    ("akia", "aws"),
    ("github", "github"),
    ("ghp_", "github"),
    ("gitlab", "gitlab"),
    ("glpat", "gitlab"),
    ("slack", "slack"),
    ("xoxb", "slack"),
    ("stripe", "stripe"),
    ("sk_live", "stripe"),
    ("azure", "azure"),
    ("sonar", "sonar"),
    ("snyk", "snyk"),
    ("1password", "1password"),
    ("vault", "vault"),
    ("jwt", "jwt"),
    ("postgres", "postgres"),
    ("mysql", "mysql"),
    ("mongodb", "mongodb"),
    ("redis", "redis"),
    ("twilio", "twilio"),
    ("sendgrid", "sendgrid"),
    ("mailgun", "mailgun"),
    ("heroku", "heroku"),
    ("digitalocean", "digitalocean"),
    ("cloudflare", "cloudflare"),
    ("datadog", "datadog"),
    ("openai", "openai"),
    ("anthropic", "anthropic"),
)


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
    try:
        with urlopen_resilient(zip_url, timeout=180) as resp:
            payload = resp.read()
    except URLError as exc:
        raise RuntimeError(f"Unable to download {zip_url}: {exc}") from exc
    with zipfile.ZipFile(io.BytesIO(payload)) as zf:
        top = zf.namelist()[0].split("/")[0]
        extract_root = dest.parent / f"_zip_{dest.name}"
        if extract_root.exists():
            shutil.rmtree(extract_root)
        zf.extractall(extract_root)
        (extract_root / top).rename(dest)
        shutil.rmtree(extract_root, ignore_errors=True)


def urlopen_resilient(url: str, *, timeout: int = 120):
    """HTTP GET with SSL retry (unverified) for broken local CA stores."""
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


def fetch_url_text(url: str, cache_path: Path | None = None) -> str:
    if cache_path and cache_path.is_file():
        log.info("Using cached %s", cache_path)
        return cache_path.read_text(encoding="utf-8", errors="replace")
    log.info("Fetching %s", url)
    try:
        with urlopen_resilient(url, timeout=120) as resp:
            text = resp.read().decode("utf-8", errors="replace")
    except URLError as exc:
        if cache_path and cache_path.is_file():
            log.warning("Fetch failed (%s); using stale cache %s", exc, cache_path)
            return cache_path.read_text(encoding="utf-8", errors="replace")
        raise RuntimeError(f"Failed to fetch {url}: {exc}") from exc
    if cache_path:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(text, encoding="utf-8")
    return text


def normalize_fingerprint(text: str) -> set[str]:
    tokens = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]{2,}", text.lower())
    skip = {"token", "secret", "fake", "example", "string", "const", "var"}
    return {t for t in tokens if t not in skip}


def similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()


def normalize_provider(rule_id: str, keywords: Iterable[str] = (), regex: str = "") -> str:
    blob = " ".join([rule_id, regex, *keywords]).lower()
    for needle, canonical in PROVIDER_ALIASES:
        if needle in blob:
            return canonical
    slug = re.sub(r"[^a-z0-9]+", "-", rule_id.lower()).strip("-")
    return slug.split("-")[0] if slug else rule_id.lower()


def var_name_from_rule(rule_id: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", rule_id).upper().strip("_")
    if not slug:
        return "API_TOKEN"
    if not slug.endswith(("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")):
        slug += "_TOKEN"
    return slug


def is_git_safe_secret(secret: str) -> bool:
    """Reject TruffleHog test tokens that trip GitHub push protection."""
    upper = secret.upper()
    if any(marker in upper for marker in ("FAKE", "EXAMPLE", "HEXVIBE", "REDACTED", "YOUR_")):
        return True
    if len(secret) < 16:
        return True
    # High-entropy / vendor-shaped tokens from upstream tests.
    if re.match(r"^(ghp_|gho_|ghu_|ghs_|sgp_|slk_|sq0atp-|AKIA|sk_live_|sk_test_)", secret):
        return False
    if re.match(r"^NT[gk]", secret):
        return False
    if re.match(r"^cli_[0-9]{10,}", secret):
        return False
    if ".atlasv1." in secret:
        return False
    if len(secret) >= 24 and re.fullmatch(r"[A-Za-z0-9+/=_\-.]{24,}", secret):
        return False
    return True


def normalize_secret_for_git(secret: str, rule_id: str, keywords: Iterable[str] = (), regex: str = "") -> str:
    if is_git_safe_secret(secret):
        return secret
    return synthesize_secret_from_regex(regex, list(keywords), rule_id)


def synthesize_safe_pattern(var: str) -> list[str]:
    return [
        f'{var} = os.getenv("{var}")',
        f"# or: {var} = vault.get_secret(\"{var}\")",
    ]


def synthesize_anti_pattern(var: str, secret: str) -> list[str]:
    safe_secret = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff]", "", secret)
    safe_secret = safe_secret.replace('"', "'").replace("\n", " ").replace("\r", " ")[:120]
    return [f'{var} = "{safe_secret}"']


def synthesize_secret_from_regex(regex: str, keywords: list[str], rule_id: str) -> str:
    for kw in keywords:
        k = kw.strip().lower().strip("'\"")
        for prefix, template in FAKE_SECRET_TEMPLATES.items():
            if prefix in k or k.startswith(prefix.rstrip("-_")):
                return template
        if len(k) >= 3:
            return f"{k.upper()}_FAKE_{rule_id[:12].replace('-', '_').upper()}"

    blob = regex.lower()
    for prefix, template in FAKE_SECRET_TEMPLATES.items():
        if prefix in blob:
            return template

    literal = re.search(r"([A-Za-z0-9]{2,8}[-_][A-Za-z0-9]{2,8})", regex)
    if literal:
        base = literal.group(1)
        return f"{base}FAKE{rule_id[:6].replace('-', '').upper()}"

    return f"fake_{rule_id.replace('-', '_')}_credential"


def gitleaks_regex_to_python(regex: str) -> str:
    """Best-effort RE2 → Python ``re`` translation for sample matching."""
    py = regex
    py = py.replace("(?i)", "(?i)")
    py = re.sub(r"\(\?i\)", "(?i)", py)
    # Gitleaks uses \z for end-of-string; Python uses \Z
    py = py.replace("\\z", "\\Z")
    return py


def extract_secret_via_secret_group(
    regex: str,
    secret_group: int,
    keywords: list[str],
    rule_id: str,
) -> str | None:
    """Use Gitleaks ``secretGroup`` capture index against synthetic assignment lines."""
    if secret_group < 1:
        return None
    fake = synthesize_secret_from_regex(regex, keywords, rule_id)
    lines = [
        f'{kw}="{fake}"' for kw in keywords[:6] if kw
    ] or [f'API_TOKEN="{fake}"', f"token = {fake}"]
    try:
        cre = re.compile(gitleaks_regex_to_python(regex), re.I | re.M)
    except re.error as exc:
        log.debug("secretGroup regex compile failed for %s: %s", rule_id, exc)
        return None
    for line in lines:
        try:
            m = cre.search(line)
        except re.error:
            continue
        if not m:
            continue
        try:
            return m.group(secret_group)
        except IndexError:
            continue
    return None


def resolve_gitleaks_secret(
    rule: dict[str, Any],
    regex: str,
    keywords: list[str],
    rule_id: str,
) -> str:
    secret_group = rule.get("secretGroup")
    if isinstance(secret_group, int) and secret_group >= 1:
        extracted = extract_secret_via_secret_group(regex, secret_group, keywords, rule_id)
        if extracted:
            return extracted
    sample = try_regex_sample(regex)
    if sample:
        return sample
    return synthesize_secret_from_regex(regex, keywords, rule_id)


def try_regex_sample(regex: str, timeout_chars: int = 400) -> str | None:
    """Best-effort: derive a short sample token from a regex literal prefix."""
    if len(regex) > timeout_chars:
        regex = regex[:timeout_chars]
    m = re.search(r"([a-zA-Z0-9_]{2,10})[-_\\][a-zA-Z0-9_{}\[\].\\+-]{2,40}", regex)
    if not m:
        return None
    prefix = m.group(1)
    if prefix.lower() in {"true", "false", "null", "match", "group"}:
        return None
    return synthesize_secret_from_regex(regex, [prefix], prefix)


# ---------------------------------------------------------------------------
# TOML parsing (stdlib tomllib + regex fallback)
# ---------------------------------------------------------------------------


def parse_gitleaks_toml(text: str) -> list[dict[str, Any]]:
    if tomllib is not None:
        try:
            data = tomllib.loads(text)
            rules = data.get("rules")
            if isinstance(rules, list):
                return [r for r in rules if isinstance(r, dict)]
        except Exception as exc:
            log.warning("tomllib parse failed, using regex fallback: %s", exc)

    rules: list[dict[str, Any]] = []
    for block in re.split(r"(?=^\[\[rules\]\])", text, flags=re.M):
        block = block.strip()
        if not block.startswith("[[rules]]"):
            continue
        rule: dict[str, Any] = {}
        id_m = re.search(r'^id\s*=\s*"([^"]+)"', block, re.M)
        if id_m:
            rule["id"] = id_m.group(1)
        desc_m = re.search(r'^description\s*=\s*"([^"]*)"', block, re.M)
        if desc_m:
            rule["description"] = desc_m.group(1)
        regex_m = re.search(r"^regex\s*=\s*'''(.+?)'''", block, re.M | re.S)
        if not regex_m:
            regex_m = re.search(r'^regex\s*=\s*"((?:\\.|[^"\\])*)"', block, re.M)
        if regex_m:
            rule["regex"] = regex_m.group(1)
        kw_m = re.search(r"^keywords\s*=\s*\[(.*?)\]", block, re.M | re.S)
        if kw_m:
            rule["keywords"] = re.findall(r'"([^"]+)"', kw_m.group(1))
        sg_m = re.search(r"^secretGroup\s*=\s*(\d+)", block, re.M)
        if sg_m:
            rule["secretGroup"] = int(sg_m.group(1))
        if rule.get("id") and rule.get("regex"):
            rules.append(rule)
    return rules


# ---------------------------------------------------------------------------
# TruffleHog Go parsing (regex-based, no AST)
# ---------------------------------------------------------------------------

RE_GO_MUST_COMPILE = re.compile(
    r"regexp\.MustCompile\(`((?:\\.|[^`\\])*)`\s*\)|"
    r"regexp\.MustCompile\(\"((?:\\.|[^\"\\])*)\"\s*\)",
    re.S,
)
RE_GO_KEYWORDS = re.compile(
    r"func\s+\([^)]*\)\s*Keywords\(\)[^{]*\{[^}]*return\s+\[\]string\{([^}]+)\}",
    re.S,
)
RE_GO_KEYWORDS_ALT = re.compile(
    r"func\s+\([^)]*\)\s*Keywords\(\)\s*\[\]string\s*\{[^}]*return\s+\[\]string\{([^}]+)\}",
    re.S,
)
RE_GO_TEST_SECRET = re.compile(
    r"(?:valid[A-Za-z0-9_]*|secret|testSecret|testToken)\s*=\s*\"([^\"\\]{8,})\"",
)
RE_GO_TEST_JSON_SECRET = re.compile(
    r'"[a-zA-Z0-9_]+"\s*:\s*"([^"\\]{12,})"',
)


def parse_go_keywords(source: str) -> list[str]:
    for pat in (RE_GO_KEYWORDS, RE_GO_KEYWORDS_ALT):
        m = pat.search(source)
        if m:
            return [s.strip().strip('"') for s in re.findall(r'"([^"]+)"', m.group(1))]
    return []


def parse_go_regexes(source: str) -> list[str]:
    out: list[str] = []
    for m in RE_GO_MUST_COMPILE.finditer(source):
        raw = m.group(1) or m.group(2) or ""
        if raw and len(raw) <= 500:
            out.append(raw)
    return out


def parse_go_test_secrets(test_source: str) -> list[str]:
    secrets: list[str] = []
    for m in RE_GO_TEST_SECRET.finditer(test_source):
        val = m.group(1)
        if "?" not in val and "invalid" not in m.group(0).lower():
            secrets.append(val)
    for m in RE_GO_TEST_JSON_SECRET.finditer(test_source):
        val = m.group(1)
        if len(val) >= 12 and not val.startswith("http"):
            secrets.append(val)
    # dedupe preserve order
    seen: set[str] = set()
    uniq: list[str] = []
    for s in secrets:
        if s in seen:
            continue
        seen.add(s)
        uniq.append(s)
    return uniq[:3]


# ---------------------------------------------------------------------------
# Markdown / persistence
# ---------------------------------------------------------------------------


def split_md_cells(line: str) -> list[str]:
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    return [p.strip() for p in re.split(r"(?<!\\)\|", s)]


def load_pattern_index(patterns_path: Path, id_prefix: str) -> PatternIndex:
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
        if not METRIC_ID_RE.match(mid) and not mid.startswith(("SEC-", "SEC-GL-", "SEC-TH-")):
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


def is_duplicate(idx: PatternIndex, rule: SecretRule) -> tuple[bool, str]:
    cid = rule.check_id.upper()
    if cid in idx.check_ids:
        return True, f"check id {rule.check_id} already present"
    anti_fp = normalize_fingerprint("\n".join(rule.anti_lines))
    anti_joined = "\n".join(rule.anti_lines)
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


def lines_to_md_cell(lines: list[str]) -> str:
    if not lines:
        return "`N/A`"
    escaped = [ln.replace("|", "\\|").replace("`", "'") for ln in lines]
    return "<br>".join(f"`{ln}`" for ln in escaped)


def lines_to_fix_template(lines: list[str]) -> str:
    flat = " ".join(lines).replace("|", "\\|")
    return flat[:400] + ("..." if len(flat) > 400 else "") or DEFAULT_FIX


def build_semantic_anchor(metric_id: str, title: str, anti_lines: list[str]) -> str:
    blob = " ".join([metric_id.lower(), title.lower(), " ".join(anti_lines[:4]).lower()])
    tokens: list[str] = []
    seen: set[str] = set()
    for t in re.findall(r"[a-z0-9]{2,}", blob.replace("_", " ")):
        if t in seen:
            continue
        seen.add(t)
        tokens.append(t)
        if len(tokens) >= 20:
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


def next_metric_id(idx: PatternIndex, prefix: str) -> str:
    n = idx.max_ids.get(prefix, 0) + 1
    idx.max_ids[prefix] = n
    return f"{prefix}-{n:03d}"


# ---------------------------------------------------------------------------
# Extractors
# ---------------------------------------------------------------------------


class SecretsExtractor(ABC):
    scanner_name: str = "secrets"

    @abstractmethod
    def extract(self) -> list[SecretRule]:
        ...


class GitleaksExtractor(SecretsExtractor):
    scanner_name = "gitleaks"

    def __init__(self, toml_text: str) -> None:
        self.toml_text = toml_text

    def extract(self) -> list[SecretRule]:
        rules = parse_gitleaks_toml(self.toml_text)
        log.info("Gitleaks: parsed %d [[rules]] entries", len(rules))
        out: list[SecretRule] = []
        seen: set[str] = set()
        for rule in rules:
            try:
                item = self._rule_to_secret(rule)
            except Exception as exc:
                log.debug("Gitleaks skip rule %s: %s", rule.get("id"), exc)
                continue
            if not item or item.check_id in seen:
                continue
            seen.add(item.check_id)
            out.append(item)
        log.info("Gitleaks extracted %d rules", len(out))
        return out

    def _rule_to_secret(self, rule: dict[str, Any]) -> SecretRule | None:
        rule_id = str(rule.get("id") or "").strip()
        regex = str(rule.get("regex") or "").strip()
        if not rule_id or not regex:
            return None
        keywords = [str(k) for k in (rule.get("keywords") or []) if k]
        description = str(rule.get("description") or rule_id).strip()
        secret = resolve_gitleaks_secret(rule, regex, keywords, rule_id)
        secret = normalize_secret_for_git(secret, rule_id, keywords, regex)
        var = var_name_from_rule(rule_id)
        provider = normalize_provider(rule_id, keywords, regex)
        title = f"Gitleaks: {description[:100]}"
        if len(description) > 100:
            title += "..."
        return SecretRule(
            check_id=f"GITLEAKS_{rule_id.upper()}",
            metric_prefix="SEC-GL",
            title=title,
            anti_lines=synthesize_anti_pattern(var, secret),
            safe_lines=synthesize_safe_pattern(var),
            source=f"Gitleaks {rule_id}",
            scanner=self.scanner_name,
            provider_key=provider,
        )


class TrufflehogExtractor(SecretsExtractor):
    scanner_name = "trufflehog"

    def __init__(self, repo: Path) -> None:
        self.repo = repo
        self.detectors_root = repo / "pkg" / "detectors"

    def extract(self) -> list[SecretRule]:
        if not self.detectors_root.is_dir():
            raise FileNotFoundError(f"TruffleHog detectors dir missing: {self.detectors_root}")
        out: list[SecretRule] = []
        seen: set[str] = set()
        go_files = sorted(self.detectors_root.rglob("*.go"))
        log.info("TruffleHog: scanning %d Go files under pkg/detectors", len(go_files))

        # Group by detector package directory (parent of .go file, skip _test.go grouping)
        packages: dict[Path, dict[str, list[Path]]] = {}
        for go_path in go_files:
            pkg_dir = go_path.parent
            kind = "test" if go_path.name.endswith("_test.go") else "main"
            packages.setdefault(pkg_dir, {"main": [], "test": []})[kind].append(go_path)

        for pkg_dir, files in sorted(packages.items(), key=lambda kv: str(kv[0])):
            if not files["main"]:
                continue
            try:
                item = self._package_to_secret(pkg_dir, files["main"], files["test"])
            except Exception as exc:
                log.debug("TruffleHog skip %s: %s", pkg_dir, exc)
                continue
            if not item or item.check_id in seen:
                continue
            seen.add(item.check_id)
            out.append(item)

        log.info("TruffleHog extracted %d detector rules", len(out))
        return out

    def _detector_slug(self, pkg_dir: Path) -> str:
        rel = pkg_dir.relative_to(self.detectors_root)
        return str(rel).replace("\\", "/").replace("/", "-")

    def _package_to_secret(
        self,
        pkg_dir: Path,
        main_files: list[Path],
        test_files: list[Path],
    ) -> SecretRule | None:
        slug = self._detector_slug(pkg_dir)
        regexes: list[str] = []
        keywords: list[str] = []
        test_secrets: list[str] = []

        for path in main_files:
            try:
                src = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                log.debug("Cannot read %s: %s", path, exc)
                continue
            regexes.extend(parse_go_regexes(src))
            keywords.extend(parse_go_keywords(src))

        for path in test_files:
            try:
                src = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            test_secrets.extend(parse_go_test_secrets(src))

        if not regexes and not test_secrets and not keywords:
            return None

        secret = test_secrets[0] if test_secrets else ""
        if secret:
            secret = normalize_secret_for_git(
                secret, slug, keywords, regexes[0] if regexes else ""
            )
        if not secret and regexes:
            secret = synthesize_secret_from_regex(regexes[0], keywords, slug) or ""
        if not secret and keywords:
            secret = synthesize_secret_from_regex("", keywords, slug)
        if not secret:
            return None

        var = var_name_from_rule(slug)
        provider = normalize_provider(slug, keywords, regexes[0] if regexes else "")
        title = f"TruffleHog: {slug.replace('-', ' ')} secret detector"
        return SecretRule(
            check_id=f"TRUFFLEHOG_{slug.upper()}",
            metric_prefix="SEC-TH",
            title=title,
            anti_lines=synthesize_anti_pattern(var, secret),
            safe_lines=synthesize_safe_pattern(var),
            source=f"TruffleHog {slug}",
            scanner=self.scanner_name,
            provider_key=provider,
        )


EXTRACTORS: dict[str, type[SecretsExtractor]] = {
    "gitleaks": GitleaksExtractor,
    "trufflehog": TrufflehogExtractor,
}


def write_patterns(
    rules: Iterable[SecretRule],
    *,
    dry_run: bool,
    limit: int | None,
) -> int:
    patterns_path = SKILLS_DIR / SKILL_DIR / "patterns.md"
    indices: dict[str, PatternIndex] = {}
    imported = 0

    for rule in rules:
        if limit is not None and imported >= limit:
            break
        prefix = rule.metric_prefix
        if prefix not in indices:
            indices[prefix] = load_pattern_index(patterns_path, prefix)

        idx = indices[prefix]
        dup, reason = is_duplicate(idx, rule)
        if dup:
            log.info("SKIP %s -> %s: duplicate — %s", rule.check_id, prefix, reason)
            continue

        metric_id = next_metric_id(idx, prefix)
        anti_cell = lines_to_md_cell(rule.anti_lines)
        safe_cell = lines_to_md_cell(rule.safe_lines)
        fix_template = lines_to_fix_template(rule.safe_lines)
        anchor = build_semantic_anchor(metric_id, rule.title, rule.anti_lines)
        row = format_table_row(
            metric_id,
            rule.title,
            anti_cell,
            safe_cell,
            rule.source,
            fix_template,
            DEFAULT_EXPLOIT,
            anchor,
        )

        if dry_run:
            log.info(
                "DRY-RUN import %s -> %s [%s] provider=%s",
                rule.check_id,
                metric_id,
                SKILL_DIR,
                rule.provider_key,
            )
        else:
            try:
                append_pattern_row(patterns_path, row)
            except OSError as exc:
                log.error("FAILED write %s -> %s: %s", rule.check_id, metric_id, exc)
                continue
            idx.check_ids.add(rule.check_id.upper())
            idx.anti_fingerprints.append(
                (metric_id, normalize_fingerprint("\n".join(rule.anti_lines)))
            )
            log.info(
                "IMPORTED %s -> %s (%s) provider=%s scanner=%s",
                rule.check_id,
                metric_id,
                SKILL_DIR,
                rule.provider_key,
                rule.scanner,
            )
        imported += 1

    return imported


def run_post_pipeline(skip_sync: bool) -> None:
    if skip_sync:
        log.info("Skipping post-pipeline (--skip-sync)")
        return
    log.info("Running scripts/sync_semgrep.py ...")
    proc = run_cmd([sys.executable, "scripts/sync_semgrep.py"])
    if proc.returncode != 0:
        log.error("sync_semgrep failed:\n%s", proc.stderr.strip())
        raise RuntimeError("sync_semgrep.py failed")
    log.info("sync_semgrep.py completed OK")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Import Gitleaks/TruffleHog secret rules into patterns.md")
    p.add_argument(
        "--target",
        choices=tuple(EXTRACTORS.keys()) + ("all",),
        default="all",
        help="Scanner source (default: all)",
    )
    p.add_argument("--gitleaks-url", default=GITLEAKS_TOML_URL)
    p.add_argument("--gitleaks-file", type=Path, default=None, help="Local gitleaks.toml (skip download)")
    p.add_argument("--trufflehog-repo", type=Path, default=None)
    p.add_argument("--cache-dir", type=Path, default=CACHE_DIR)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--skip-sync", action="store_true")
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logging(args.verbose)
    global CACHE_DIR
    CACHE_DIR = args.cache_dir.resolve()

    log.info("HexVibe secrets-scanner ingest (skill=%s, stack=%s)", SKILL_DIR, STACK)
    targets = list(EXTRACTORS.keys()) if args.target == "all" else [args.target]
    all_rules: list[SecretRule] = []

    try:
        if "gitleaks" in targets:
            if args.gitleaks_file:
                toml_path = args.gitleaks_file.resolve()
                if not toml_path.is_file():
                    raise FileNotFoundError(f"Gitleaks config not found: {toml_path}")
                toml_text = toml_path.read_text(encoding="utf-8", errors="replace")
            else:
                cache_toml = CACHE_DIR / "gitleaks.toml"
                toml_text = fetch_url_text(args.gitleaks_url, cache_toml)
            all_rules.extend(GitleaksExtractor(toml_text).extract())

        if "trufflehog" in targets:
            if args.trufflehog_repo:
                repo = args.trufflehog_repo.resolve()
                if not repo.is_dir():
                    raise FileNotFoundError(f"Local TruffleHog repo not found: {repo}")
            else:
                repo = CACHE_DIR / "trufflehog"
                clone_or_update_repo(TRUFFLEHOG_REPO_URL, repo, TRUFFLEHOG_ZIP)
            all_rules.extend(TrufflehogExtractor(repo).extract())

        # Cross-scanner dedup: skip TruffleHog if Gitleaks already covers the provider.
        gitleaks_rules = [r for r in all_rules if r.scanner == "gitleaks"]
        gitleaks_providers = {r.provider_key for r in gitleaks_rules}
        truffle_rules = [
            r
            for r in all_rules
            if r.scanner == "trufflehog" and r.provider_key not in gitleaks_providers
        ]
        skipped_th = len(all_rules) - len(gitleaks_rules) - len(truffle_rules)
        if skipped_th:
            log.info(
                "Cross-scanner dedup: skipped %d TruffleHog rules (provider overlap with Gitleaks)",
                skipped_th,
            )
        filtered = gitleaks_rules + truffle_rules

        imported = write_patterns(filtered, dry_run=args.dry_run, limit=args.limit)
        if imported and not args.dry_run:
            run_post_pipeline(args.skip_sync)
        elif imported == 0:
            log.info("No new secret patterns imported")
        else:
            log.info("Dry-run complete (%d would import)", imported)

        log.info(
            "Done. New patterns: %d / candidates after cross-scanner filter: %d / raw: %d",
            imported,
            len(filtered),
            len(all_rules),
        )
        return 0
    except Exception:
        log.exception("Secrets ingest failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
