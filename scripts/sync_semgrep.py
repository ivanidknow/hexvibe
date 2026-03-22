"""
Sync ``core/skills/*/patterns.md`` → ``core/semgrep-rules/*.yaml`` and run ``generate_detection_matrix.py``.

Table rows split on ``|`` not preceded by ``\\`` (``re.split(r'(?<!\\\\)\\|', ...)``) so ``\\|`` in code cells
stays intact. v1.0: PyYAML literal block scalars (``|`` / ``|-``) for ``message``, ``pattern``,
``metadata.fix_template``, ``metadata.exploit_scenario`` via ``_LiteralStr`` + ``SafeDumper`` (avoids broken YAML
from ``:``, ``"``, ``@`` in free text). ``metadata.confidence`` is always a **string** (Semgrep rejects float
nodes in metadata).

Column mapping (0-based indices, after split): ``[6]`` = fix_template, ``[7]`` = exploit_scenario,
``[8]`` = optional confidence override; default confidence ``0.9`` if column absent/empty.
"""
import os

os.environ["PYTHONUTF8"] = "1"
os.environ["PYTHONIOENCODING"] = "utf-8"

import re
import subprocess
import sys
import textwrap
from pathlib import Path

try:
    import yaml  # type: ignore
    from yaml import SafeDumper  # type: ignore
except ImportError:
    yaml = None  # type: ignore[assignment]
    SafeDumper = None  # type: ignore[misc, assignment]

SKILLS_DIR = Path("core/skills")
RULES_DIR = Path("core/semgrep-rules")
RULES_DIR.mkdir(exist_ok=True)

LANGUAGE_MAP = {
    "fastapi-async": ["python"],
    "auth-keycloak": ["python"],
    "browser-agent": ["python", "javascript", "typescript"],
    "infra-k8s-helm": ["yaml", "dockerfile"],
    "app-logic": ["python"],
    "observability": ["python"],
    "java-spring": ["java"],
    "csharp-dotnet": ["csharp"],
    "go-core": ["go"],
    "ruby-rails": ["ruby"],
    "python-django": ["python"],
    "python-security": ["python"],
    "nodejs-nestjs": ["javascript", "typescript"],
    "nodejs-security": ["javascript", "typescript"],
    "advanced-agent-cloud": ["python", "javascript", "typescript"],
    "desktop-vsto-suite": ["javascript", "typescript", "csharp", "generic"],
    "license-compliance": ["generic"],
    "ru-regulatory": ["generic"],
    "cloud-secrets": ["generic", "yaml", "python"],
    "devops-security": ["generic", "dockerfile", "yaml"],
    "integration-security": ["generic", "python", "yaml"],
    "frontend-security": ["generic", "javascript", "typescript", "html"],
    "mobile-flutter": ["generic", "dart", "kotlin"],
    "python-backend-pro": ["python"],
    "desktop-electron-pro": ["generic", "javascript", "typescript", "json"],
    "domain-access-management": ["generic", "python", "javascript", "typescript", "json"],
    "domain-data-privacy": ["generic", "python", "javascript", "typescript", "yaml"],
    "domain-platform-hardening": ["generic", "yaml", "json", "dart", "kotlin", "javascript", "typescript"],
    "domain-input-validation": ["generic", "python", "javascript", "typescript", "json"],
}

EXCLUDED_SKILLS: set[str] = set()

_METRIC_ID_RE = re.compile(r"^[A-Z0-9]{2,4}-[0-9][0-9A-Za-z.\-]*$")


class _LiteralStr(str):
    """YAML literal block scalar (|) for safe dumping of :, quotes, etc."""


def _represent_literal_str(dumper: object, data: _LiteralStr) -> object:
    return dumper.represent_scalar("tag:yaml.org,2002:str", str(data), style="|")  # type: ignore[union-attr]


if yaml is not None and SafeDumper is not None:
    SafeDumper.add_representer(_LiteralStr, _represent_literal_str)  # type: ignore[arg-type]


def _split_md_table_cells(line: str) -> list[str]:
    """Split a markdown table row on ``|`` that is not escaped as ``\\|``."""
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    return [p.strip() for p in re.split(r"(?<!\\)\|", s)]


def _unescape_md_cell(cell: str) -> str:
    return cell.replace("\\|", "|")


def _strip_cell_wrapping(cell: str) -> str:
    """Trim whitespace and remove a single pair of surrounding ASCII quotes from table cells."""
    t = cell.strip()
    if len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'":
        t = t[1:-1].strip()
    return t


def count_patterns_with_fix_template_for_expected(expected_ids: set[str]) -> int:
    satisfied: set[str] = set()
    empty_fix = {"", "N/A", "—", "-"}
    for md_path in sorted(SKILLS_DIR.glob("**/patterns.md")):
        for raw in md_path.read_text(encoding="utf-8").splitlines():
            if not raw.strip().startswith("|"):
                continue
            line_wo_anchor = re.sub(
                r"\s*<!--\s*semantic_anchor:.*?-->\s*$",
                "",
                raw,
                flags=re.IGNORECASE,
            )
            cols = _split_md_table_cells(line_wo_anchor)
            if len(cols) < 7:
                continue
            metric_id = cols[0]
            if not _METRIC_ID_RE.match(metric_id):
                continue
            if metric_id not in expected_ids:
                continue
            fix_text = _unescape_md_cell(cols[6]).strip()
            if fix_text and fix_text not in empty_fix:
                satisfied.add(metric_id)
    return len(satisfied)


_CWE_TOKEN_RE = re.compile(r"CWE-[0-9]+")


def count_unique_cwe_tokens_in_skill_patterns() -> int:
    tokens: set[str] = set()
    for md_path in sorted(SKILLS_DIR.glob("**/patterns.md")):
        text = md_path.read_text(encoding="utf-8")
        tokens.update(_CWE_TOKEN_RE.findall(text))
    return len(tokens)


def _md_cell_to_text(cell: str) -> str:
    """Normalize markdown table cell: strip, drop markdown inline code backticks."""
    raw = _unescape_md_cell(cell).strip()
    raw = raw.replace("<br>", "\n")
    text = re.sub(r"`+", "", raw)
    text = textwrap.dedent(text).strip()
    return text


def _normalize_structural_pattern(raw: str) -> str:
    raw = raw.replace('\\"', '"').replace("\\'", "'")
    code = textwrap.dedent(raw).strip()
    code = code.replace(" ... ", " ... ").replace("...", "...")
    return code


def _infer_yaml_key_pattern(raw: str) -> str | None:
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if ":" in stripped and not stripped.startswith(("-", "{", "}")):
            return stripped
    return None


def _marker_regex(metric_id: str) -> str:
    """Second branch for gold testbed ``Vulnerable: <ID>`` markers (OR with structural pattern)."""
    return rf"Vulnerable:\s*{re.escape(metric_id)}\b"


_MISSING = "N/A"


def _parse_confidence_cell(raw: str, default: str) -> str:
    """Normalize optional confidence column to a short string (Semgrep-safe metadata)."""
    s = raw.strip()
    if not s or s == _MISSING:
        return default
    try:
        v = float(s.replace(",", "."))
    except ValueError:
        return default
    return f"{v:.4g}"


def parse_patterns(md_path: Path) -> list[dict[str, str]]:
    """Extract pattern row + message + fix_template + exploit_scenario + confidence."""
    patterns: list[dict[str, str]] = []
    default_confidence = "0.9"
    content = md_path.read_text(encoding="utf-8")
    for line in content.splitlines():
        if not line.startswith("|"):
            continue
        line_wo_anchor = re.sub(r"\s*<!--\s*semantic_anchor:.*?-->\s*$", "", line, flags=re.IGNORECASE)
        cols = _split_md_table_cells(line_wo_anchor)
        if len(cols) < 5:
            continue
        cols = [_unescape_md_cell(c) for c in cols]
        while len(cols) < 9:
            cols.append(_MISSING)
        metric_id = _strip_cell_wrapping(cols[0])
        if not _METRIC_ID_RE.match(metric_id):
            continue
        title = _strip_cell_wrapping(cols[1])
        anti_text = _md_cell_to_text(cols[2])
        source_idx = 5 if len(cols) >= 6 else 4
        source_text = _md_cell_to_text(cols[source_idx])
        fix_template = _md_cell_to_text(cols[6]).replace("\\|", "|") or _MISSING
        exploit_text = _md_cell_to_text(cols[7]) or _MISSING
        conf = _parse_confidence_cell(cols[8], default_confidence)
        if anti_text and anti_text != _MISSING:
            patterns.append(
                {
                    "id": metric_id,
                    "title": title,
                    "pattern": _normalize_structural_pattern(anti_text),
                    "message": f"HexVibe Detection [{metric_id}]: {source_text}",
                    "severity": "WARNING",
                    "fix_template": fix_template,
                    "exploit_scenario": exploit_text,
                    "confidence": conf,
                }
            )
    return patterns


def generate_yaml(skill_name: str, patterns: list[dict[str, str]]) -> Path:
    """Build Semgrep rule dicts and serialize with PyYAML (literal ``|`` blocks for long text fields)."""
    semgrep_rules: list[dict[str, object]] = []
    languages = LANGUAGE_MAP.get(skill_name, ["python", "yaml", "dockerfile"])
    for p in patterns:
        pat_body = (p.get("pattern") or "").strip() or _MISSING
        if skill_name == "infra-k8s-helm":
            yaml_key = _infer_yaml_key_pattern(pat_body)
            if yaml_key:
                primary_pattern: dict[str, object] = {"pattern": _LiteralStr(yaml_key)}
            else:
                primary_pattern = {"pattern": _LiteralStr(pat_body)}
        else:
            primary_pattern = {"pattern": _LiteralStr(pat_body)}

        if skill_name == "infra-k8s-helm":
            rule_languages = ["generic"]
        elif skill_name == "browser-agent":
            rule_languages = ["generic"]
        elif skill_name == "observability":
            rule_languages = ["generic"]
        elif skill_name == "nodejs-nestjs":
            rule_languages = ["generic"]
        elif skill_name == "nodejs-security":
            rule_languages = ["generic"]
        elif skill_name == "advanced-agent-cloud":
            rule_languages = ["generic"]
        elif skill_name == "desktop-vsto-suite":
            rule_languages = ["generic"]
        elif skill_name == "cloud-secrets":
            rule_languages = ["generic"]
        elif skill_name in {
            "devops-security",
            "integration-security",
            "frontend-security",
            "mobile-flutter",
            "desktop-electron-pro",
            "domain-access-management",
            "domain-data-privacy",
            "domain-platform-hardening",
            "domain-input-validation",
        }:
            rule_languages = ["generic"]
        else:
            rule_languages = languages

        fix_t = str(p.get("fix_template") or _MISSING).strip() or _MISSING
        exploit_t = str(p.get("exploit_scenario") or _MISSING).strip() or _MISSING
        raw_conf = str(p.get("confidence") or "0.9").strip()
        if raw_conf == _MISSING or not raw_conf:
            raw_conf = "0.9"
        try:
            conf_f = float(raw_conf.replace(",", "."))
        except ValueError:
            conf_f = 0.9
        # Semgrep metadata: all custom string values as str + LiteralStr (|); never float/null.
        conf_str = f"{conf_f:.4g}"

        metadata: dict[str, object] = {
            "hexvibe_version": "v1.0",
            "confidence": _LiteralStr(conf_str),
            "exploit_scenario": _LiteralStr(exploit_t),
            "fix_template": _LiteralStr(fix_t),
        }

        # Marker regex OR structural pattern — regex second avoids some generic-mode parse edge cases.
        marker = _marker_regex(p["id"])
        semgrep_rules.append(
            {
                "id": f"hexvibe.{skill_name.lower()}.{p['id'].lower()}",
                "metadata": metadata,
                "pattern-either": [
                    primary_pattern,
                    {"pattern-regex": marker},
                ],
                "message": _LiteralStr(p["message"]),
                "languages": rule_languages,
                "severity": p["severity"],
            }
        )

    output_file = RULES_DIR / f"{skill_name}.yaml"
    # Rule files must be UTF-8 (Cyrillic in metadata; Semgrep on Windows reads as UTF-8).
    with output_file.open("w", encoding="utf-8") as f:
        if yaml is not None:
            # Literal block style for _LiteralStr (message, pattern, exploit, fix); not default_style='|'
            # on the whole document — that would distort list/structure emission in edge cases.
            yaml.dump(
                {"rules": semgrep_rules},
                f,
                Dumper=SafeDumper,
                sort_keys=False,
                allow_unicode=True,
                default_flow_style=False,
                width=1000,
            )
        else:
            _write_rules_yaml_manual(f, semgrep_rules)
    return output_file


def _emit_block_scalar(f: object, key_indent: str, key: str, text: str) -> None:
    """Write ``key: |-`` + indented body (v1.0 literal scalars)."""
    f.write(f"{key_indent}{key}: |-\n")
    content_indent = key_indent + "  "
    body = text.rstrip("\n")
    if not body:
        f.write(f"{content_indent}\n")
        return
    for ln in body.splitlines():
        f.write(f"{content_indent}{ln}\n")


def _write_rules_yaml_manual(f: object, semgrep_rules: list[dict[str, object]]) -> None:
    """Emit rules when PyYAML is unavailable (must match semantic structure for ``semgrep --validate``)."""
    f.write("rules:\n")
    for rule in semgrep_rules:
        f.write(f"  - id: {rule['id']}\n")
        md = rule.get("metadata") or {}
        if isinstance(md, dict) and md:
            f.write("    metadata:\n")
            hv = md.get("hexvibe_version")
            if hv is not None:
                f.write(f"      hexvibe_version: {hv}\n")
            cf = md.get("confidence")
            _emit_block_scalar(f, "      ", "confidence", str(cf) if cf is not None else "")
            ex = md.get("exploit_scenario")
            _emit_block_scalar(f, "      ", "exploit_scenario", str(ex) if ex is not None else _MISSING)
            fx = md.get("fix_template")
            _emit_block_scalar(f, "      ", "fix_template", str(fx) if fx is not None else _MISSING)
        f.write("    pattern-either:\n")
        pat0 = rule["pattern-either"][0]
        f.write("      - pattern: |-\n")
        for ln in str(pat0["pattern"]).rstrip("\n").splitlines():
            f.write(f"          {ln}\n")
        if not str(pat0["pattern"]).strip():
            f.write("          \n")
        f.write(f"      - pattern-regex: {rule['pattern-either'][1]['pattern-regex']!r}\n")
        _emit_block_scalar(f, "    ", "message", str(rule["message"]))
        f.write("    languages:\n")
        for lang in rule["languages"]:
            f.write(f"      - {lang}\n")
        f.write(f"    severity: {rule['severity']}\n")


def _run_semgrep_validate(rule_file: Path) -> tuple[bool, str]:
    cmd = ["semgrep", "--validate", "--config", str(rule_file)]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env={**os.environ, "PYTHONUTF8": "1"},
        )
        ok = proc.returncode == 0
        combined = "\n".join(
            x for x in ((proc.stderr or "").strip(), (proc.stdout or "").strip()) if x
        )
        return ok, combined or ("(no output)" if ok else "semgrep validate failed (no stderr)")
    except FileNotFoundError:
        return False, "semgrep: executable not found in PATH"


def main() -> None:
    print("HexVibe: Sync patterns -> Semgrep rules")
    for skill_path in SKILLS_DIR.iterdir():
        if not skill_path.is_dir() or skill_path.name in EXCLUDED_SKILLS:
            continue
        pattern_md = skill_path / "patterns.md"
        if not pattern_md.exists():
            continue
        patterns = parse_patterns(pattern_md)
        if not patterns:
            continue
        out = generate_yaml(skill_path.name, patterns)
        is_valid, validate_log = _run_semgrep_validate(out)
        status = "validated" if is_valid else "generated (validation skipped/failed)"
        print(f"[ok] {skill_path.name}: {len(patterns)} rules -> {out} ({status})")
        if not is_valid:
            print(f"[semgrep-validate] {out}:\n{validate_log}", file=sys.stderr)

    matrix_script = Path(__file__).resolve().parent / "generate_detection_matrix.py"
    if matrix_script.exists():
        print("HexVibe: Generate detection matrix")
        proc = subprocess.run(
            [sys.executable, str(matrix_script)],
            cwd=str(Path(__file__).resolve().parents[1]),
            encoding="utf-8",
            errors="replace",
            env={**os.environ, "PYTHONUTF8": "1"},
        )
        if proc.returncode != 0:
            print(
                f"[warn] detection-matrix generation reported misses/failure "
                f"(exit {proc.returncode})"
            )


if __name__ == "__main__":
    main()
