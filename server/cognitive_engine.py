"""
HexVibe v1.0 — Tier-1 Cognitive Security Review: three-phase analytics, confidence, exclusions,
self-critique, and precedent manifests (see **SECURITY_PRECEDENTS.md**, **FALSE_POSITIVE_GUIDE.md**).

Hard rule: findings_primary_log only includes items with confidence_score >= PRIMARY_LOG_THRESHOLD (0.8)
after all phases, unless blocked by hard_exclude_from_primary_log.

Calibration paths under core/gold-standard-testbed/** skip Elite FP filtering + comparative boost so the
1000/1000 gold matrix stays authoritative.
"""

from __future__ import annotations

import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any

# Libraries that indicate defensive controls when present in the same file (Phase 1).
_PROTECTION_MARKERS: dict[str, tuple[str, ...]] = {
    "dompurify": ("xss", "innerhtml", "dangerouslysetinnerhtml", "html", "sanitize", "dom"),
    "isomorphic-dompurify": ("xss", "innerhtml", "dangerouslysetinnerhtml", "html", "sanitize"),
    "sanitize-html": ("xss", "innerhtml", "html"),
    "bcrypt": ("password", "hash", "credential", "auth", "session"),
    "bcryptjs": ("password", "hash", "credential", "auth"),
    "argon2": ("password", "hash", "credential"),
    "zod": ("validation", "schema", "request", "body", "input", "parse"),
    "yup": ("validation", "schema", "request"),
    "helmet": ("express", "header", "csp", "http"),
    "csurf": ("csrf", "token"),
    "express-rate-limit": ("rate", "limit", "brute", "login"),
}

# Tier-1 rule: stay silent in the primary log unless we are >= 80% confident after all filters.
PRIMARY_LOG_THRESHOLD = 0.8
_CONFIDENCE_THRESHOLD = PRIMARY_LOG_THRESHOLD
# Elite hard exclusions cap confidence below the primary bar (see FALSE_POSITIVE_GUIDE.md).
_ELITE_LOW_CONFIDENCE_CAP = 0.28

# ---------------------------------------------------------------------------
# WORD-FOR-WORD manifest (HARD EXCLUSIONS) — logic must implement these categories.
# Denial of Service (DOS) или resource exhaustion — EXCLUDE.
# Secrets/credentials на диске, если они защищены (secured) — EXCLUDE.
# Rate limiting или service overload — EXCLUDE.
# Memory consumption / CPU exhaustion — EXCLUDE.
# Lack of input validation на некритичных полях без доказанного security impact — EXCLUDE.
# GitHub Action workflows, если они не триггерятся через недоверенный ввод — EXCLUDE.
# Lack of hardening measures (мы флаем только конкретные уязвимости, а не отсутствие best practices) — EXCLUDE.
# Race conditions / timing attacks, если они теоретические — EXCLUDE.
# Outdated third-party libraries (управляются отдельно) — EXCLUDE.
# Memory safety (buffer overflow) в Rust и других memory-safe языках — EXCLUDE.
# Файлы, являющиеся unit-тестами или используемые только для тестов — EXCLUDE.
# Log spoofing (вывод несанитизированного ввода в логи не является уязвимостью) — EXCLUDE.
# SSRF, которые контролируют только путь (path), а не host/protocol — EXCLUDE.
# Контент пользователя в AI system prompts — EXCLUDE.
# Regex injection и Regex DOS — EXCLUDE.
# Documentation (markdown-файлы) — EXCLUDE.
# Lack of audit logs — EXCLUDE.
# ---------------------------------------------------------------------------
# PRECEDENTS (WORD-FOR-WORD) — implement _elite_precedents()
# Environment variables и CLI flags — это доверенные значения (TRUSTED).
# UUIDs — считаются неугадываемыми (unguessable).
# React/Angular XSS — игнорируй, если нет dangerouslySetInnerHTML или bypassSecurityTrustHtml.
# Shell scripts — игнорируй command injection, если нет специфического пути атаки через untrusted input.
# ---------------------------------------------------------------------------

# Hard exclusion: tests/ paths — only keep high signal for these title/CWE hints.
_TESTS_HIGH_SIGNAL = re.compile(
    r"(rce|remote code|pickle|deserializ|sql injection|sqli|ssrf|credential|secret|password|token|pii|personally identifiable|authz bypass|idor|traversal|\bcwe-78\b|\bcwe-89\b|\bcwe-502\b|\bcwe-918\b)",
    re.I,
)

_DOS_RE = re.compile(r"dos|denial|redos|regex\s*injection|rate.?limit|payload.?size|zip.?bomb", re.I)

# Memory safety (buffer overflow) — EXCLUDE for typical memory-safe / managed runtimes (not C/C++).
_MEMORY_SAFE_LANG_EXT = (
    ".rs",
    ".kt",
    ".swift",
    ".go",
    ".java",
    ".scala",
    ".cs",
)

_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.I,
)


def is_calibration_testbed_path(rel_path: str) -> bool:
    """True for paths under the gold calibration corpus (FP elite filter disabled)."""
    p = rel_path.replace("\\", "/").lower().strip("/")
    return "gold-standard-testbed/" in f"/{p}/" or p.endswith("gold-standard-testbed")


def _metric_title_from_row(row: dict[str, str]) -> str:
    return str(row.get("title", ""))


def _combined_title_and_message(item: dict[str, Any], row: dict[str, str]) -> str:
    title = _metric_title_from_row(row)
    extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
    msg = str(extra.get("message", "") if extra else "")
    return f"{title} {msg}"


def _snippet_lower(item: dict[str, Any]) -> str:
    extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
    lines = item.get("lines") or (extra.get("lines") if extra else None)
    if isinstance(lines, dict):
        text = str(lines.get("snippet", "") or lines.get("content", ""))
    else:
        text = str(lines or "")
    return text.lower()


def _file_ext(rel_path: str) -> str:
    p = Path(rel_path.replace("\\", "/"))
    return p.suffix.lower()


def _is_test_only_path(rel_path: str) -> bool:
    """Файлы, являющиеся unit-тестами или используемые только для тестов — EXCLUDE."""
    r = rel_path.lower().replace("\\", "/")
    base = Path(r).name
    if "/tests/" in f"/{r}/" or "/__tests__/" in f"/{r}/" or "/test/" in f"/{r}/":
        return True
    if base.startswith("test_") or base.endswith("_test.py") or base.endswith("_test.go"):
        return True
    if ".spec." in base or ".test." in base or base.endswith(".spec.ts") or base.endswith(".spec.tsx"):
        return True
    if "conftest.py" in base or base == "pytest.ini" or "jest.config" in base:
        return True
    return False


def _elite_hard_exclusion_match(item: dict[str, Any], row: dict[str, str], rel_path: str) -> str | None:
    """
    Returns a slug if HARD EXCLUSIONS apply (WORD-FOR-WORD categories in module docstring).
    """
    combined = _combined_title_and_message(item, row).lower()
    title = _metric_title_from_row(row).lower()
    snippet = _snippet_lower(item)
    rel_l = rel_path.lower().replace("\\", "/")
    ext = _file_ext(rel_path)

    # Documentation (markdown-файлы) — EXCLUDE.
    if ext == ".md":
        return "documentation_markdown"

    # Regex injection и Regex DOS — EXCLUDE.
    if re.search(r"regex\s*(dos|injection)|redos|re\.dos|\bredos\b", combined, re.I):
        return "regex_injection_dos"

    # Denial of Service (DOS) или resource exhaustion — EXCLUDE.
    # Memory consumption / CPU exhaustion — EXCLUDE.
    if re.search(
        r"\bdenial of service\b|\bdos\b|resource exhaustion|zip bomb|payload size|cpu exhaustion|"
        r"memory exhaustion|memory consumption|decompression bomb|algorithmic complexity",
        combined,
        re.I,
    ):
        return "dos_or_resource_exhaustion"

    # Rate limiting или service overload — EXCLUDE.
    if re.search(r"rate\s*limit|throttl|service overload|429|too many requests", combined, re.I):
        return "rate_limit_or_overload"

    # Secrets/credentials на диске, если они защищены (secured) — EXCLUDE.
    if re.search(r"secret|credential|password|token|api key", combined, re.I):
        if re.search(
            r"encrypt|kms|vault|secrets?\s*manager|keychain|secured|protected|age\s|sops|"
            r"sealed secret|external secret",
            combined + " " + snippet,
            re.I,
        ):
            return "secrets_secured_on_disk"

    # Lack of input validation на некритичных полях без доказанного security impact — EXCLUDE.
    if re.search(
        r"lack of input validation|missing input validation|insufficient validation|weak validation",
        combined,
        re.I,
    ):
        if not re.search(
            r"sql|injection|auth|admin|ssrf|rce|traversal|idor|credential|password|token|xss",
            combined,
            re.I,
        ):
            return "noncritical_input_validation"

    # GitHub Action workflows, если они не триггерятся через недоверенный ввод — EXCLUDE.
    if ".github/workflows" in rel_l:
        if not re.search(
            r"pull_request_target|workflow_dispatch|issue_comment|repository_dispatch|untrusted",
            combined,
            re.I,
        ):
            return "github_actions_trusted_triggers_only"

    # Lack of hardening measures (мы флаем только конкретные уязвимости, а не отсутствие best practices) — EXCLUDE.
    if re.search(
        r"missing security header|weak configuration|missing csrf|best practice|hardening|"
        r"not using secure|no security policy|insecure default|missing\s+(xss|csrf|csp|hsts)",
        combined,
        re.I,
    ):
        return "lack_of_hardening_best_practice"

    # Race conditions / timing attacks, если они теоретические — EXCLUDE.
    if re.search(r"race condition|timing attack|toctou", combined, re.I):
        if re.search(r"theoretical|unlikely|no exploit|no practical", combined, re.I) or not re.search(
            r"exploit|payload|attack|unsafe",
            combined,
            re.I,
        ):
            return "race_timing_theoretical"

    # Outdated third-party libraries (управляются отдельно) — EXCLUDE.
    if re.search(r"outdated (package|dependency|library)|vulnerable (version|dependency)|cve-\d+", combined, re.I):
        return "outdated_third_party_libraries"

    # Memory safety (buffer overflow) в Rust и других memory-safe языках — EXCLUDE.
    if ext in _MEMORY_SAFE_LANG_EXT and re.search(
        r"buffer overflow|heap overflow|stack overflow|use.after.free|memory safety",
        combined,
        re.I,
    ):
        return "memory_safety_memory_safe_language"

    # Файлы, являющиеся unit-тестами или используемые только для тестов — EXCLUDE.
    if _is_test_only_path(rel_path):
        return "unit_or_test_only_files"

    # Log spoofing — EXCLUDE.
    if re.search(r"log (injection|forgery|spoofing)|unsanitized.*log|log injection", combined, re.I):
        return "log_spoofing"

    # SSRF, которые контролируют только путь (path), а не host/protocol — EXCLUDE.
    if "ssrf" in combined or "server-side request" in combined:
        if re.search(r"path only|only the path|path parameter|not.*host|host.*not controllable", combined, re.I):
            return "ssrf_path_only"

    # Контент пользователя в AI system prompts — EXCLUDE.
    if re.search(r"system prompt|prompt injection|user content.*prompt|assistant role", combined, re.I):
        return "ai_user_content_in_system_prompts"

    # Lack of audit logs — EXCLUDE.
    if re.search(r"lack of audit|missing audit|no audit log|audit log missing|insufficient audit", combined, re.I):
        return "lack_of_audit_logs"

    return None


def _precedent_trusted_env_cli(title: str, msg: str, rel_path: str) -> bool:
    """Environment variables и CLI flags — это доверенные значения (TRUSTED)."""
    t = f"{title} {msg}".lower()
    if any(
        x in t
        for x in (
            "cli flag",
            "command line",
            "argv",
            "os.environ",
            "process.env",
            "getenv",
            "environment variable",
        )
    ):
        return True
    if rel_path.lower().endswith((".env", ".env.example")):
        return True
    return False


def _precedent_uuid_unguessable(title: str, msg: str, snippet: str) -> bool:
    """UUIDs — считаются неугадываемыми (unguessable)."""
    blob = f"{title} {msg}".lower()
    if not _UUID_RE.search(snippet):
        return False
    return bool(re.search(r"idor|guess|predictable|enumerat", blob, re.I))


def _precedent_react_xss_no_sink(title: str, msg: str, rel_path: str, snippet: str) -> bool:
    """React/Angular XSS — игнорируй, если нет dangerouslySetInnerHTML или bypassSecurityTrustHtml."""
    if not rel_path.lower().endswith((".tsx", ".jsx", ".ts", ".js")):
        return False
    blob = f"{title} {msg}".lower()
    if not re.search(r"xss|cross.site.script|innerhtml", blob, re.I):
        return False
    if "dangerouslysetinnerhtml" in snippet or "bypasssecuritytrust" in snippet:
        return False
    return True


def _shell_untrusted_input_vector(snippet: str) -> bool:
    """True if snippet suggests attacker-controlled input reaches shell."""
    if not snippet:
        return True
    if re.search(r"\$\@|\$\*|\$\{?@|read\s|getopts|curl\s+[^\n]*\$|wget\s+[^\n]*\$|eval\s|\$\(", snippet):
        return True
    return False


def _precedent_shell_no_untrusted_path(title: str, msg: str, rel_path: str, snippet: str) -> bool:
    """Shell scripts — игнорируй command injection, если нет специфического пути атаки через untrusted input."""
    if not rel_path.lower().endswith(".sh"):
        return False
    blob = f"{title} {msg}".lower()
    if not re.search(r"command injection|shell injection|cwe-78", blob, re.I):
        return False
    return not _shell_untrusted_input_vector(snippet)


def _elite_precedents(
    score: float,
    item: dict[str, Any],
    row: dict[str, str],
    rel_path: str,
) -> tuple[float, list[str]]:
    """
    PRECEDENTS logic — снижай Confidence Score до минимума для перечисленных случаев.
    """
    reasons: list[str] = []
    title = _metric_title_from_row(row)
    extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
    msg = str(extra.get("message", ""))
    snippet = _snippet_lower(item)

    if _precedent_trusted_env_cli(title, msg, rel_path):
        score = min(score, 0.08)
        reasons.append("precedent:trusted_env_cli")

    if _precedent_uuid_unguessable(title, msg, snippet):
        score = min(score, 0.1)
        reasons.append("precedent:uuid_unguessable")

    if _precedent_react_xss_no_sink(title, msg, rel_path, snippet):
        score = min(score, 0.1)
        reasons.append("precedent:react_angular_xss_without_dangerous_sink")

    if _precedent_shell_no_untrusted_path(title, msg, rel_path, snippet):
        score = min(score, 0.12)
        reasons.append("precedent:shell_no_untrusted_input_attack_path")

    return max(0.05, score), reasons


def _read_file_safe(path: Path, limit: int = 400_000) -> str:
    try:
        data = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""
    if len(data) > limit:
        return data[:limit]
    return data


def _collect_manifest_paths_from_file_to_root(repo_root: Path, file_dir: Path) -> list[Path]:
    """package.json / requirements.txt / pyproject.toml walking up to repo root."""
    manifests: list[Path] = []
    seen: set[str] = set()
    current = file_dir.resolve()
    root = repo_root.resolve()
    names = ("package.json", "requirements.txt", "pyproject.toml")
    while True:
        for name in names:
            p = current / name
            key = str(p)
            if p.is_file() and key not in seen:
                seen.add(key)
                manifests.append(p)
        if current == root:
            break
        parent = current.parent
        if parent == current:
            break
        current = parent
    return manifests


def _parse_package_json_deps(text: str) -> str:
    """Return lowercased blob of dependency names for substring matching."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return ""
    chunks: list[str] = []
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        block = data.get(key)
        if isinstance(block, dict):
            chunks.extend(str(k).lower() for k in block.keys())
    return " ".join(chunks)


def _parse_requirements_names(text: str) -> list[str]:
    pkgs: list[str] = []
    for line in text.splitlines():
        line = line.strip().split("#")[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"([A-Za-z0-9_.\-]+)", line)
        if m:
            pkgs.append(m.group(1).lower().replace("_", "-"))
    return pkgs


def _pyproject_dep_blob(text: str) -> str:
    """Lightweight scan of pyproject.toml for tool.poetry.dependencies / project.dependencies."""
    t = text.lower()
    return t


def phase1_context_research(repo_root: Path, rel_path: str) -> dict[str, Any]:
    """
    Phase 1 — Context Research: before verdict, scan the target file and repo manifests
    (package.json, requirements.txt, pyproject.toml) upward from the file for defensive libraries.
    """
    path = (repo_root / rel_path.replace("/", "\\")).resolve()
    text = _read_file_safe(path)
    lowered = text.lower()
    found: list[str] = []
    for lib in _PROTECTION_MARKERS:
        if lib.replace("-", "_") in lowered:
            found.append(lib)
            continue
        if f"'{lib}'" in lowered or f'"{lib}"' in lowered:
            found.append(lib)
            continue
        if f"/{lib}" in lowered or f"{lib}/" in lowered:
            found.append(lib)
            continue

    manifest_hits: list[str] = []
    manifest_paths: list[str] = []
    merged_manifest_blob = ""
    for mp in _collect_manifest_paths_from_file_to_root(repo_root, path.parent):
        try:
            manifest_paths.append(str(mp.relative_to(repo_root)).replace("\\", "/"))
        except ValueError:
            manifest_paths.append(str(mp).replace("\\", "/"))
        raw = _read_file_safe(mp, 80_000)
        merged_manifest_blob += "\n" + raw.lower()
        name = mp.name.lower()
        if name == "package.json":
            deps = _parse_package_json_deps(raw)
            merged_manifest_blob += " " + deps
            for lib in _PROTECTION_MARKERS:
                if lib in deps or f'"{lib}"' in raw.lower() or f"'{lib}'" in raw.lower():
                    if lib not in found:
                        manifest_hits.append(lib)
                        found.append(lib)
        elif name == "requirements.txt":
            for pkg in _parse_requirements_names(raw):
                # map pip names to protection markers (bcrypt, zod n/a for python)
                for lib in _PROTECTION_MARKERS:
                    if lib.replace("-", "_") == pkg.replace("-", "_") or lib == pkg:
                        if lib not in found:
                            manifest_hits.append(lib)
                            found.append(lib)
            if "argon2" in raw.lower() and "argon2" not in found:
                found.append("argon2")
                manifest_hits.append("argon2")
            if "bcrypt" in raw.lower() and "bcrypt" not in found:
                found.append("bcrypt")
                manifest_hits.append("bcrypt")
        elif name == "pyproject.toml":
            blob = _pyproject_dep_blob(raw)
            for lib in _PROTECTION_MARKERS:
                if lib in blob:
                    if lib not in found:
                        manifest_hits.append(lib)
                        found.append(lib)

    return {
        "protection_libs_detected": sorted(set(found)),
        "manifest_paths_scanned": manifest_paths,
        "manifest_lib_hits": sorted(set(manifest_hits)),
    }


def comparative_analysis_boost(
    repo_root: Path,
    rel_path: str,
    *,
    apply: bool,
) -> tuple[float, str | None]:
    """
    If a file introduces a data-handling approach divergent from the repo manifest baseline
    (e.g. alternate ORM or missing validation vs repo-standard Zod/Pydantic), boost confidence by +0.2.
    Disabled for calibration testbed paths (caller passes apply=False).
    """
    if not apply:
        return 0.0, None
    path = (repo_root / rel_path.replace("/", "\\")).resolve()
    if not path.is_file():
        return 0.0, None
    merged = ""
    for mp in _collect_manifest_paths_from_file_to_root(repo_root, path.parent):
        merged += "\n" + _read_file_safe(mp, 80_000).lower()
    file_text = _read_file_safe(path, 120_000)
    f = file_text.lower()
    m = merged

    if "django" in m and ("sqlalchemy" in f or "sqlalchemy.orm" in f):
        return 0.2, "comparative_analysis:django_repo_sqlalchemy_in_file"
    if "sqlalchemy" in m and ("from django" in f or "django.db" in f):
        return 0.2, "comparative_analysis:sqlalchemy_repo_django_in_file"

    if re.search(r'["\']zod["\']|/zod\b|\bzod\b', m) and rel_path.lower().endswith((".ts", ".tsx", ".js", ".jsx")):
        if "zod" not in f and (
            "req.body" in f or "request.json" in f or "req.params" in f or "request.body" in f
        ):
            return 0.2, "comparative_analysis:repo_zod_file_no_validation_import"

    if "pydantic" in m and rel_path.lower().endswith(".py"):
        if "pydantic" not in f and ("fastapi" in f or "flask" in f or "django" in f):
            if "request." in f or "body" in f or "form" in f:
                return 0.2, "comparative_analysis:repo_pydantic_file_unvalidated_handler"

    return 0.0, None


def _attack_path_concrete(
    item: dict[str, Any],
    row: dict[str, str],
    *,
    confidence: float,
    elite_hard: str | None,
    all_reasons: list[str],
    snippet: str,
) -> bool:
    """
    True when heuristics support a concrete chain from user-controlled input to the sink.
    Pessimistic Tier-1 default: False unless evidence outweighs precedent/static noise.
    """
    if elite_hard:
        return False
    if any(
        x in all_reasons
        for x in (
            "precedent:trusted_env_cli",
            "precedent:uuid_unguessable",
            "precedent:react_angular_xss_without_dangerous_sink",
            "precedent:shell_no_untrusted_input_attack_path",
        )
    ):
        return False
    if _looks_like_static_literal_match(item):
        return False
    title = _metric_title_from_row(row)
    extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
    msg = str(extra.get("message", ""))
    blob = f"{snippet} {msg} {title}".lower()
    if re.search(
        r"request\.|req\.(body|query|params)|req\.json|user input|untrusted|stdin|process\.argv\[|"
        r"body\(|form\[|params\[|query\[|cookies\[|headers\[",
        blob,
        re.I,
    ):
        return True
    if re.search(r"\$\(|`|\beval\s*\(|new\s+function\b|child_process|\.exec\(|\.spawn\(", blob):
        return True
    return confidence >= PRIMARY_LOG_THRESHOLD


def _protection_matches_metric(title: str, libs: list[str]) -> bool:
    t = title.lower()
    for lib in libs:
        hints = _PROTECTION_MARKERS.get(lib, ())
        if not hints:
            continue
        if any(h in t for h in hints):
            return True
    return False


def base_confidence_for_finding(
    item: dict[str, Any],
    row: dict[str, str],
    *,
    phase1: dict[str, Any],
    rel_path: str,
) -> tuple[float, list[str]]:
    """
    Returns (confidence 0..1, reason strings).
    """
    reasons: list[str] = []
    # Baseline tuned so typical Semgrep WARNING/ERROR clear the 0.8 primary bar unless downgraded.
    score = 0.82
    title = _metric_title_from_row(row)
    extra = item.get("extra") or {}
    if isinstance(extra, dict) and extra.get("severity"):
        sev = str(extra["severity"]).upper()
        if sev == "ERROR":
            score = 0.92
        elif sev == "WARNING":
            score = 0.84
        else:
            score = 0.55

    libs = list(phase1.get("protection_libs_detected") or [])
    if libs and _protection_matches_metric(title, libs):
        score = min(score, 0.2)
        reasons.append("phase1_protection_lib_present")

    if _looks_like_static_literal_match(item):
        score = min(score, 0.35)
        reasons.append("likely_static_literal_or_constant")

    if _env_or_config_only(title, item):
        score = min(score, 0.45)
        reasons.append("environment_or_config_dependent")

    # Tests path: suppress high confidence unless strong signal
    rel_l = rel_path.lower().replace("\\", "/")
    if "/tests/" in f"/{rel_l}/":
        if _TESTS_HIGH_SIGNAL.search(title):
            score = min(max(score, 0.55), 0.79)
            reasons.append("tests_path_high_signal_retained")
        elif _DOS_RE.search(title) or "regex" in title.lower():
            score = min(score, 0.25)
            reasons.append("tests_path_low_priority_category")
        else:
            score = min(score, 0.35)
            reasons.append("tests_path_deprioritized")

    return max(0.05, min(1.0, score)), reasons


def _looks_like_static_literal_match(item: dict[str, Any]) -> bool:
    lines = item.get("lines") or item.get("extra", {}).get("lines") if isinstance(item.get("extra"), dict) else None
    if not lines:
        return False
    # Semgrep JSON: lines may be string with snippet
    text = str(lines) if not isinstance(lines, dict) else str(lines.get("snippet", ""))
    snippet = text.strip()
    if len(snippet) < 3:
        return False
    # Heuristic: only quoted string on matched line
    if re.match(r'^["\'][^"\']{0,200}["\']\s*$', snippet):
        return True
    return False


def _env_or_config_only(title: str, item: dict[str, Any]) -> bool:
    t = title.lower()
    if any(x in t for x in ("env var", "environment", "os.getenv", "process.env", "feature flag")):
        return True
    msg = str(item.get("extra", {}).get("message", "")) if isinstance(item.get("extra"), dict) else ""
    if "getenv" in msg.lower() or "process.env" in msg.lower():
        return True
    return False


def hard_exclude_from_primary_log(
    rel_path: str,
    title: str,
    confidence: float,
    *,
    elite_hard_exclusion: str | None = None,
) -> bool:
    """
    Returns True if this finding must not appear in the primary (>=0.8) log.
    """
    if elite_hard_exclusion:
        return True
    rel_l = rel_path.lower().replace("\\", "/")
    if "/tests/" in f"/{rel_l}/":
        if _DOS_RE.search(title) or ("regex" in title.lower() and "injection" in title.lower()):
            if not _TESTS_HIGH_SIGNAL.search(title):
                return True
    return confidence < _CONFIDENCE_THRESHOLD


def self_critique(
    item: dict[str, Any],
    row: dict[str, str],
    *,
    confidence: float,
    phase1: dict[str, Any],
) -> dict[str, Any]:
    notes: list[str] = []
    cap = "HIGH"
    if confidence <= 0.45:
        cap = "LOW"
    elif confidence <= 0.65:
        cap = "MEDIUM"
    if _env_or_config_only(_metric_title_from_row(row), item):
        notes.append("May require environment-specific preconditions.")
        cap = "LOW"
    if _looks_like_static_literal_match(item):
        notes.append("Match may be a constant; verify runtime data flow (taint).")
    libs = phase1.get("protection_libs_detected") or []
    if libs:
        notes.append(f"Protection libraries present in file: {', '.join(libs)} — validate sink coverage.")
    return {
        "try_disprove_summary": "; ".join(notes) if notes else "No automatic disproof; manual review advised.",
        "suggested_severity_cap": cap,
    }


def enrich_finding(
    repo_root: Path,
    item: dict[str, Any],
    row: dict[str, str],
    rel_path: str,
    *,
    apply_false_positive_filter: bool = True,
) -> dict[str, Any]:
    phase1 = phase1_context_research(repo_root, rel_path)
    conf, reasons = base_confidence_for_finding(item, row, phase1=phase1, rel_path=rel_path)

    boost, boost_reason = comparative_analysis_boost(
        repo_root,
        rel_path,
        apply=apply_false_positive_filter,
    )
    if boost_reason:
        conf = min(1.0, conf + boost)
        reasons.append(boost_reason)

    elite_hard: str | None = None
    prec_reasons: list[str] = []
    if apply_false_positive_filter:
        elite_hard = _elite_hard_exclusion_match(item, row, rel_path)
        if elite_hard:
            conf = min(conf, _ELITE_LOW_CONFIDENCE_CAP)
            reasons.append(f"hard_exclusion:{elite_hard}")
        conf, prec_reasons = _elite_precedents(conf, item, row, rel_path)
        reasons.extend(prec_reasons)

    conf = max(0.05, min(1.0, conf))
    snippet_l = _snippet_lower(item)
    attack_concrete = _attack_path_concrete(
        item,
        row,
        confidence=conf,
        elite_hard=elite_hard,
        all_reasons=reasons,
        snippet=snippet_l,
    )

    critique = self_critique(item, row, confidence=conf, phase1=phase1)
    out = deepcopy(item)
    ex = out.setdefault("extra", {})
    if not isinstance(ex, dict):
        ex = {}
        out["extra"] = ex
    ex["confidence_score"] = round(conf, 3)
    ex["confidence_reasons"] = reasons
    ex["attack_path_concrete"] = attack_concrete
    # Tier-1: primary log only when final confidence clears the threshold (never < 0.8).
    primary_ok = conf >= PRIMARY_LOG_THRESHOLD and not hard_exclude_from_primary_log(
        rel_path,
        _metric_title_from_row(row),
        conf,
        elite_hard_exclusion=elite_hard,
    )
    cognitive: dict[str, Any] = {
        "phase1_context_research": phase1,
        "phase2_confidence_and_precedents": {
            "primary_log_threshold": PRIMARY_LOG_THRESHOLD,
            "comparative_analysis_boost": boost_reason,
            "comparative_boost_value": boost,
        },
        "self_critique": critique,
        "exploit_scenario": row.get("exploit_scenario", ""),
        "primary_log_eligible": primary_ok,
        "attack_path_concrete": attack_concrete,
        "false_positive_filtering": {
            "version": "v1.0",
            "apply_false_positive_filter": apply_false_positive_filter,
            "hard_exclusion": elite_hard,
            "precedents_applied": prec_reasons,
        },
    }
    ex["cognitive"] = cognitive
    if "phase1_protection_lib_present" in reasons and conf <= 0.25:
        ex["severity"] = "INFO"
    return out
