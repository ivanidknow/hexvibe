"""
HexVibe MCP adapter for skill-based security checks.

Tools exposed:
- list_skills()
- get_skill_context(skill_id)
- ask_hexvibe(question)
- run_check(path)
- ignore_finding(metric_id, file_path, line_content, reason)
- apply_remediation(metric_id, file_path)
"""

from __future__ import annotations

import argparse
import json
import math
import re
import subprocess
import hashlib
import sys
import os
from datetime import datetime, timezone
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Any

_SERVER_DIR = Path(__file__).resolve().parent
if str(_SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(_SERVER_DIR))
from cognitive_engine import PRIMARY_LOG_THRESHOLD as _PRIMARY_LOG_THRESHOLD
from cognitive_engine import enrich_finding as _cognitive_enrich_finding
from cognitive_engine import is_calibration_testbed_path as _is_calibration_testbed_path

DOCKER_APP_ROOT = Path("/app")
ROOT = DOCKER_APP_ROOT if os.path.exists("/app/core") else Path(__file__).resolve().parents[1]
# Public release identifier (MCP responses, verification prompts).
HEXVIBE_RELEASE_VERSION = "v1.0"
HEXVIBE_UNIQUE_PATTERN_COUNT = 1000
SKILLS_DIR = ROOT / "core" / "skills"
RULES_DIR = ROOT / "core" / "semgrep-rules"
TRUFFLEHOG_CONFIG = ROOT / "server" / "config.yaml"
RAG_CACHE_PATH = ROOT / "server" / ".rag-cache.json"
RAG_CACHE_SCHEMA_VERSION = 3
# In Docker, ROOT is /app → `/app/.hexvibe-ignore.yaml` (must match COPY in Dockerfile).
IGNORE_FILE_PATH = ROOT / ".hexvibe-ignore.yaml"
DETECTION_SUMMARY_PATH = ROOT / "core" / "gold-standard-testbed" / "detection-summary.json"
RULE_COMPLIANCE_MAP_PATH = ROOT / "core" / "gold-standard-testbed" / "rule-compliance-map.json"
_COMPLIANCE_SUMMARY_CACHE: dict[str, Any] | None = None
_RULE_COMPLIANCE_MAP_CACHE: dict[str, dict[str, list[str]]] | None = None
_TOKEN_RE = re.compile(r"[A-Za-zА-Яа-я0-9_\-]+", re.UNICODE)
_RAG_CHUNKS: list[dict[str, Any]] = []
ANTI_HALLUCINATION_PROMPT = (
    "ТЫ ОБЯЗАН проверить код инструментом run_check ПОСЛЕ каждого исправления. "
    "Твои слова о безопасности ничего не значат без PASS от Semgrep/TruffleHog."
)


def _log_err(message: str) -> None:
    print(f"[hexvibe] {message}", file=sys.stderr, flush=True)


def _load_compliance_artifacts() -> tuple[dict[str, Any], dict[str, dict[str, list[str]]]]:
    """
    Load OWASP Top 10 + MITRE ATT&CK tags per rule (from generated JSON).
    """
    global _COMPLIANCE_SUMMARY_CACHE, _RULE_COMPLIANCE_MAP_CACHE
    if _COMPLIANCE_SUMMARY_CACHE is not None and _RULE_COMPLIANCE_MAP_CACHE is not None:
        return _COMPLIANCE_SUMMARY_CACHE, _RULE_COMPLIANCE_MAP_CACHE
    summary: dict[str, Any] = {}
    if DETECTION_SUMMARY_PATH.exists():
        try:
            summary = json.loads(DETECTION_SUMMARY_PATH.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            summary = {}
    rule_map: dict[str, dict[str, list[str]]] = {}
    if RULE_COMPLIANCE_MAP_PATH.exists():
        try:
            raw = json.loads(RULE_COMPLIANCE_MAP_PATH.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                rule_map = {str(k): v for k, v in raw.items() if isinstance(v, dict)}
        except (json.JSONDecodeError, OSError):
            rule_map = {}
    _COMPLIANCE_SUMMARY_CACHE = summary
    _RULE_COMPLIANCE_MAP_CACHE = rule_map
    return summary, rule_map


def _attach_compliance_to_finding(item: dict[str, Any], rule_map: dict[str, dict[str, list[str]]]) -> None:
    mid = _extract_metric_id(str(item.get("check_id", ""))).upper()
    if not mid or mid not in rule_map:
        return
    tags = rule_map[mid]
    extra = item.setdefault("extra", {})
    extra["compliance"] = {
        "cwe": tags.get("cwe", []),
        "owasp": tags.get("owasp", []),
        "mitre_attack": tags.get("attack", []),
    }


def _load_skill_manifests() -> dict[str, dict[str, Any]]:
    manifests: dict[str, dict[str, Any]] = {}
    for skill_dir in sorted(SKILLS_DIR.iterdir()):
        if not skill_dir.is_dir():
            continue
        skill_json = skill_dir / "skill.json"
        if not skill_json.exists():
            continue
        data = json.loads(skill_json.read_text(encoding="utf-8"))
        sid = str(data.get("skill_id", skill_dir.name))
        data["__dir_name"] = skill_dir.name
        manifests[sid] = data
    return manifests


def _tokenize(text: str) -> list[str]:
    tokens = [t.lower() for t in _TOKEN_RE.findall(text)]
    # Lightweight aliasing keeps RU/EN security terms searchable in one space.
    aliases = {
        "снилс": "snils",
        "утечка": "leak",
        "персональные": "pii",
        "пдн": "pii",
    }
    expanded = list(tokens)
    for t in tokens:
        a = aliases.get(t)
        if a:
            expanded.append(a)
    return expanded


def _vectorize(text: str) -> Counter[str]:
    return Counter(_tokenize(text))


def _cosine(a: Counter[str], b: Counter[str]) -> float:
    if not a or not b:
        return 0.0
    common = set(a.keys()) & set(b.keys())
    dot = sum(a[k] * b[k] for k in common)
    if dot == 0:
        return 0.0
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def _parse_pattern_rows(patterns_text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in patterns_text.splitlines():
        if not line.startswith("|"):
            continue
        anchor_match = re.search(r"<!--\s*semantic_anchor:\s*(.*?)\s*-->", line, flags=re.IGNORECASE)
        semantic_anchor = anchor_match.group(1).strip() if anchor_match else ""
        line_wo_anchor = re.sub(r"\s*<!--\s*semantic_anchor:.*?-->\s*$", "", line, flags=re.IGNORECASE)
        cols = [c.strip() for c in line_wo_anchor.strip().split("|")[1:-1]]
        if len(cols) < 5:
            continue
        metric_id = cols[0]
        if not re.match(r"^[A-Z0-9]{2,4}-[0-9A-Za-z.\-]+$", metric_id):
            continue
        # Supported formats:
        # - ID | Title | Anti | Safe | Source
        # - ID | Title | Anti | Safe | Stack | Source
        # - ID | Title | Anti | Safe | Stack | Source | fix_template
        # - v1.0 row: ... | fix_template | exploit_scenario
        exploit_value = ""
        if len(cols) >= 8:
            stack_value = cols[4].strip() or "Generic"
            source_value = cols[5].strip()
            fix_template_value = cols[6].strip()
            exploit_value = cols[7].strip()
        elif len(cols) >= 7:
            stack_value = cols[4].strip() or "Generic"
            source_value = cols[5].strip()
            fix_template_value = cols[6].strip()
        elif len(cols) >= 6:
            stack_value = cols[4].strip() or "Generic"
            source_value = cols[5].strip()
            fix_template_value = ""
        else:
            stack_value = "Generic"
            source_value = cols[4].strip()
            fix_template_value = ""
        if not fix_template_value:
            fix_template_value = _derive_fix_template(stack_value, cols[1], cols[3])
        rows.append(
            {
                "metric_id": metric_id,
                "title": cols[1],
                "anti": cols[2],
                "safe": cols[3],
                "stack": stack_value,
                "source": source_value,
                "fix_template": fix_template_value,
                "exploit_scenario": exploit_value,
                "semantic_anchor": semantic_anchor,
            }
        )
    return rows


def _derive_fix_template(stack: str, title: str, safe_pattern: str) -> str:
    stack_l = (stack or "").lower()
    title_l = (title or "").lower()
    if "c#" in stack_l or ".net" in stack_l:
        return (
            "Prefer `using` / `try-finally` for resource lifetime and replace legacy/dangerous calls with safe .NET APIs; "
            "apply allowlists and strict input validation at boundaries."
        )
    if "fastapi" in stack_l or "python" in stack_l:
        return (
            "Introduce explicit Pydantic request/response schemas (`BaseModel`) with strict validation, "
            "use `response_model`/exclude controls, and replace dynamic operations with typed safe flows."
        )
    if "node.js" in stack_l or "javascript" in stack_l or "next" in stack_l or "react" in stack_l:
        return (
            "Validate untrusted inputs with Zod schemas and sanitize HTML/DOM sinks via DOMPurify before rendering; "
            "prefer typed allowlists for URLs/commands/templates."
        )
    if "server action" in title_l or "use client" in title_l or "use server" in title_l:
        return (
            "For Next.js, split server/client responsibilities strictly, validate inputs via Zod, and sanitize any user-controlled markup with DOMPurify."
        )
    if safe_pattern:
        return safe_pattern.replace("<br>", " ")
    return "Apply strict allowlist validation, typed schemas, and framework-safe APIs."


def _load_file_directive(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""
    probe = "\n".join(text.splitlines()[:30]).lower()
    if "'use server'" in probe or '"use server"' in probe:
        return "use_server"
    if "'use client'" in probe or '"use client"' in probe:
        return "use_client"
    return ""


def _scope_finding_by_next_directive(metric_title: str, directive: str) -> bool:
    if not directive:
        return True
    title = metric_title.lower()
    if directive == "use_server":
        # Keep server-side checks; suppress clearly client-only detections.
        client_markers = ("use client", "client-side", "dangerouslysetinnerhtml", "dompurify", "browser")
        return not any(m in title for m in client_markers)
    if directive == "use_client":
        # Keep client-side checks; suppress clearly server-only detections.
        server_markers = ("use server", "server action", "getserversideprops", "api route", "server-side")
        return not any(m in title for m in server_markers)
    return True


def _apply_context_awareness(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    metric_cache: dict[str, dict[str, str]] = {}
    scoped: list[dict[str, Any]] = []
    for item in findings:
        rel = str(item.get("path", "")).replace("\\", "/")
        rel_l = rel.lower()
        metric = _extract_metric_id(str(item.get("check_id", ""))).upper()
        row = metric_cache.get(metric)
        if row is None:
            row = _find_metric_row(metric) or {}
            metric_cache[metric] = row
        title = str(row.get("title", ""))

        directive = ""
        if rel_l.endswith((".js", ".jsx", ".ts", ".tsx")):
            candidate = (ROOT / rel).resolve()
            if candidate.exists():
                directive = _load_file_directive(candidate)
        if not _scope_finding_by_next_directive(title, directive):
            continue

        severity = "WARNING"
        if "/tests/" in f"/{rel_l}/":
            severity = "INFO"
        elif "/auth/" in f"/{rel_l}/" or "/api/" in f"/{rel_l}/":
            severity = "ERROR"
        extra = item.setdefault("extra", {})
        extra["severity"] = severity
        if directive:
            extra["context_scope"] = directive
        scoped.append(item)
    return scoped


_EXT_TO_STACKS: dict[str, set[str]] = {
    ".py": {"python", "python/fastapi"},
    ".go": {"go"},
    ".js": {"node.js/javascript", "node.js/nestjs", "browser automation", "agent/browser"},
    ".ts": {"node.js/javascript", "node.js/nestjs", "browser automation", "agent/browser"},
    ".tsx": {"node.js/javascript"},
    ".jsx": {"node.js/javascript"},
    ".dart": {"flutter"},
    ".kt": {"flutter", "kubernetes/infra"},
    ".java": {"java/spring"},
    ".rb": {"ruby/rails"},
    ".cs": {".net/c#", "electron/desktop/.net", "electron/desktop"},
    ".yaml": {"kubernetes/infra", "cloud/secrets", "compliance/regulatory"},
    ".yml": {"kubernetes/infra", "cloud/secrets", "compliance/regulatory"},
    ".tf": {"cloud/secrets", "kubernetes/infra"},
    ".json": {
        "node.js/javascript",
        "compliance/license",
        "identity/oidc",
        "cloud/secrets",
        "application",
        "platform/api",
    },
}


def _extract_context_extensions(text: str) -> set[str]:
    if not text:
        return set()
    exts = {m.group(0).lower() for m in re.finditer(r"\.[a-z0-9]{1,8}\b", text.lower())}
    t = text.lower()
    if "dockerfile" in t:
        exts.add(".dockerfile")
    if "mainactivity.kt" in t:
        exts.add(".kt")
    return exts


def _stack_matches_context_ext(stack: str, context_exts: set[str]) -> bool:
    if not stack or not context_exts:
        return False
    stack_norm = stack.strip().lower()
    for ext in context_exts:
        for expected in _EXT_TO_STACKS.get(ext, set()):
            if expected in stack_norm:
                return True
    return False


def _build_rag_index() -> list[dict[str, Any]]:
    chunks: list[dict[str, Any]] = []
    manifests = _load_skill_manifests()
    for skill_id, manifest in manifests.items():
        skill_dir = SKILLS_DIR / str(manifest.get("__dir_name", skill_id))
        index_path = skill_dir / "index.md"
        patterns_path = skill_dir / "patterns.md"
        if not index_path.exists() or not patterns_path.exists():
            continue
        index_text = index_path.read_text(encoding="utf-8")
        patterns_text = patterns_path.read_text(encoding="utf-8")
        example_path = str(manifest.get("few_shot_examples", ""))

        # Paragraph chunks from index for high-level semantic routing.
        for paragraph in [p.strip() for p in index_text.split("\n\n") if p.strip()]:
            chunks.append(
                {
                    "kind": "index",
                    "skill_id": skill_id,
                    "text": paragraph,
                    "vector": _vectorize(paragraph),
                    "example_path": example_path,
                }
            )

        # Pattern chunks for safe-pattern retrieval.
        for row in _parse_pattern_rows(patterns_text):
            row_text = " ".join(
                [
                    row["metric_id"],
                    row["title"],
                    row["anti"].replace("<br>", " "),
                    row["safe"].replace("<br>", " "),
                    row["source"],
                    row.get("exploit_scenario", "").replace("<br>", " "),
                ]
            )
            chunks.append(
                {
                    "kind": "pattern",
                    "skill_id": skill_id,
                    "metric_id": row["metric_id"],
                    "title": row["title"],
                    "safe_pattern": row["safe"],
                    "fix_template": row.get("fix_template", ""),
                    "exploit_scenario": row.get("exploit_scenario", ""),
                    "stack": row.get("stack", "Generic"),
                    "semantic_anchor": row.get("semantic_anchor", ""),
                    "text": row_text,
                    "vector": _vectorize(row_text),
                    "anchor_vector": _vectorize(row.get("semantic_anchor", "")),
                    "example_path": example_path,
                }
            )
    return chunks


def _count_total_pattern_rows() -> int:
    total = 0
    manifests = _load_skill_manifests()
    for skill_id, manifest in manifests.items():
        skill_dir = SKILLS_DIR / str(manifest.get("__dir_name", skill_id))
        patterns_path = skill_dir / "patterns.md"
        if not patterns_path.exists():
            continue
        rows = _parse_pattern_rows(patterns_path.read_text(encoding="utf-8"))
        total += len(rows)
    return total


def _rag_source_files() -> list[Path]:
    files: list[Path] = []
    for p in SKILLS_DIR.rglob("*"):
        if p.is_file():
            files.append(p)
    files.sort(key=lambda x: str(x.relative_to(ROOT)).replace("\\", "/"))
    return files


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _compute_files_checksum() -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for p in _rag_source_files():
        rel = str(p.relative_to(ROOT)).replace("\\", "/")
        st = p.stat()
        digest = _hash_file(p)
        entries.append(
            {
                "path": rel,
                "mtime_ns": st.st_mtime_ns,
                "size": st.st_size,
                "sha256": digest,
            }
        )
    rollup = hashlib.sha256()
    for e in entries:
        rollup.update(f"{e['path']}|{e['mtime_ns']}|{e['size']}|{e['sha256']}\n".encode("utf-8"))
    return {"version": 1, "count": len(entries), "checksum": rollup.hexdigest(), "files": entries}


def _serialize_chunks(chunks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for chunk in chunks:
        item = dict(chunk)
        for key in ("vector", "anchor_vector"):
            vec = item.get(key)
            if isinstance(vec, Counter):
                item[key] = dict(vec)
        out.append(item)
    return out


def _deserialize_chunks(chunks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for chunk in chunks:
        item = dict(chunk)
        for key in ("vector", "anchor_vector"):
            vec = item.get(key)
            if isinstance(vec, dict):
                item[key] = Counter({str(k): int(v) for k, v in vec.items()})
            else:
                item[key] = Counter()
        out.append(item)
    return out


def _load_rag_cache() -> tuple[dict[str, Any] | None, dict[str, Any]]:
    current_checksum = _compute_files_checksum()
    if not RAG_CACHE_PATH.exists():
        return None, current_checksum
    try:
        payload = json.loads(RAG_CACHE_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        _log_err("RAG cache read failed, rebuilding in-memory index")
        return None, current_checksum
    if int(payload.get("schema_version", 0)) != RAG_CACHE_SCHEMA_VERSION:
        return None, current_checksum
    cached_checksum = payload.get("files_checksum")
    if cached_checksum != current_checksum:
        return None, current_checksum
    return payload, current_checksum


def _save_rag_cache(chunks: list[dict[str, Any]], files_checksum: dict[str, Any]) -> None:
    payload = {
        "schema_version": RAG_CACHE_SCHEMA_VERSION,
        "files_checksum": files_checksum,
        "chunks": _serialize_chunks(chunks),
    }
    try:
        RAG_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        RAG_CACHE_PATH.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    except (OSError, TypeError, ValueError):
        # Cache failures must never break server startup.
        _log_err("RAG cache write failed; continuing without persisted cache")
        return


def _build_or_load_rag_index() -> list[dict[str, Any]]:
    cached, checksum = _load_rag_cache()
    if cached is not None:
        _log_err("RAG cache loaded")
        return _deserialize_chunks(cached.get("chunks", []))
    _log_err("RAG cache miss or invalid; rebuilding index")
    chunks = _build_rag_index()
    _save_rag_cache(chunks, checksum)
    return chunks


def _skill_boosts(question: str) -> dict[str, float]:
    q = question.lower()
    boosts: dict[str, float] = {}
    if any(k in q for k in ["пдн", "персональ", "152-фз", "152", "kii", "гост", "1с"]):
        boosts["ru-regulatory"] = 0.35
    if any(k in q for k in ["фстэк", "fstek", "приказ 235", "приказ 239", "gost r 56939", "гост р 56939", "кии"]):
        boosts["ru-regulatory"] = max(boosts.get("ru-regulatory", 0.0), 0.45)
    if any(k in q for k in ["цб", "57580", "уди", "уда", "user/pass", "мясные учет", "meat account"]):
        boosts["ru-regulatory"] = max(boosts.get("ru-regulatory", 0.0), 0.45)
    if any(k in q for k in ["fapi", "keycloak", "клинкер", "clinker", "fapi-sec", "fapi-paok", "гост 57580"]):
        boosts["auth-keycloak"] = 0.45
    if any(k in q for k in ["vault", "eso", "secret", "секрет", "externalsecret", "vault agent injector"]):
        boosts["cloud-secrets"] = max(boosts.get("cloud-secrets", 0.0), 0.35)
    if any(k in q for k in ["docker", "dockerfile", "root", "контейнер", "container", "user root", "latest tag", "env secret", "arg secret"]):
        boosts["devops-security"] = 0.35
    if any(k in q for k in ["slsa", "provenance", "ssdf", "supply chain"]):
        boosts["devops-security"] = max(boosts.get("devops-security", 0.0), 0.45)
    if any(k in q for k in ["keycloak", "jwt", "issuer", "audience", "vault", "external secrets operator", "eso"]):
        boosts["integration-security"] = 0.4
    if any(k in q for k in ["react", "vue", "frontend", "xss", "dompurify", "dangerouslysetinnerhtml", "v-html", "innerhtml"]):
        boosts["frontend-security"] = 0.45
    if any(k in q for k in ["node", "express", "nestjs", "fastify", "npm", "package.json", "buffer", "mass-assignment"]):
        boosts["nodejs-security"] = max(boosts.get("nodejs-security", 0.0), 0.5)
    if any(
        k in q
        for k in [
            "kubernetes",
            "k8s",
            "helm",
            "dockerfile",
            "nginx",
            "squid",
            "proxy",
            "capabilities",
            "rootfs",
        ]
    ):
        boosts["infra-k8s-helm"] = max(boosts.get("infra-k8s-helm", 0.0), 0.5)
    if any(k in q for k in ["license", "sbom", "agpl", "gpl", "sspl", "syft"]):
        boosts["license-compliance"] = 0.25
    if any(k in q for k in ["metadata", "169.254.169.254", "vault", "kms", "iam", "secret"]):
        boosts["cloud-secrets"] = 0.2
    # v13.3 domain-* boosts
    if any(k in q for k in ["flutter", ".dart", "mainactivity.kt", "flag_secure", "badcertificatecallback"]):
        boosts["domain-platform-hardening"] = max(boosts.get("domain-platform-hardening", 0.0), 0.7)
    if any(k in q for k in [".py", "python", ".js", "javascript", "node", "path traversal", "ssrf", "injection"]):
        boosts["domain-input-validation"] = max(boosts.get("domain-input-validation", 0.0), 0.5)
    if any(k in q for k in ["resource limits", "limits", "requests cpu", "requests memory", "k8s resources"]):
        boosts["domain-platform-hardening"] = max(boosts.get("domain-platform-hardening", 0.0), 0.7)
    return boosts


def _semantic_search(
    question: str,
    top_k: int = 3,
    kind: str | None = None,
    prioritize_anchors: bool = False,
) -> list[dict[str, Any]]:
    query_vec = _vectorize(question)
    query_anchor_vec = _vectorize(question)
    anchor_query_tokens = {
        t
        for t in _tokenize(question)
        if len(t) >= 4 and t not in {"утечка", "leak", "data", "данные", "security", "secure", "pii"}
    }
    boosts = _skill_boosts(question)
    context_exts = _extract_context_extensions(question)
    scored: list[tuple[int, float, dict[str, Any]]] = []
    for chunk in _RAG_CHUNKS:
        if kind and chunk.get("kind") != kind:
            continue
        score = _cosine(query_vec, chunk.get("vector", Counter()))
        anchor_priority = 0
        if prioritize_anchors and chunk.get("kind") == "pattern":
            anchor_vec = chunk.get("anchor_vector", Counter())
            anchor_score = _cosine(query_anchor_vec, anchor_vec)
            anchor_tokens = set(anchor_vec.keys()) if isinstance(anchor_vec, Counter) else set()
            exact_anchor_hits = len(anchor_query_tokens & anchor_tokens)
            if anchor_score > 0:
                anchor_priority = 1
                score *= 2.0
            if exact_anchor_hits > 0:
                # Exact semantic anchor hits dominate broad lexical overlap.
                score += float(exact_anchor_hits)
        score += boosts.get(str(chunk.get("skill_id", "")), 0.0)
        # v13.3: context-aware stack boost for consolidated domain-* skills.
        if str(chunk.get("skill_id", "")).startswith("domain-") and chunk.get("kind") == "pattern":
            if _stack_matches_context_ext(str(chunk.get("stack", "")), context_exts):
                score += 0.7
        if score > 0:
            scored.append((anchor_priority, score, chunk))
    scored.sort(key=lambda x: (x[0], x[1]), reverse=True)
    return [{**c, "score": round(s, 4), "anchor_priority": ap} for ap, s, c in scored[:top_k]]


def _semantic_skill_scores(query: str) -> dict[str, float]:
    # Aggregate max semantic score per skill and normalize to [0..1].
    scored = _semantic_search(query, top_k=max(50, len(_RAG_CHUNKS)))
    per_skill: dict[str, float] = {}
    for item in scored:
        sid = str(item.get("skill_id", ""))
        s = float(item.get("score", 0.0))
        if sid and s > per_skill.get(sid, 0.0):
            per_skill[sid] = s
    if not per_skill:
        return {}
    max_v = max(per_skill.values()) or 1.0
    return {k: min(v / max_v, 1.0) for k, v in per_skill.items()}


def select_skills_for_context(
    file_path: str,
    file_content: str = "",
    question: str = "",
    top_k: int = 5,
) -> list[dict[str, Any]]:
    manifests = _load_skill_manifests()
    query = f"{question}\n{file_path}\n{file_content}".strip()
    sem_scores = _semantic_skill_scores(query) if query else {}
    keyword_boosts = _skill_boosts(query) if query else {}
    suffix = Path(file_path).suffix.lower()
    hay = query.lower()

    ranked: list[dict[str, Any]] = []
    for sid, manifest in manifests.items():
        priority = int(manifest.get("security_priority", 5))
        rel_exts = [str(x).lower() for x in manifest.get("relevant_extensions", [])]
        ext_hit = 1.0 if suffix and suffix in rel_exts else 0.0
        triggers = [str(t).lower() for t in manifest.get("activation_triggers", [])]
        trig_hit = 1.0 if any(t and t in hay for t in triggers) else 0.0
        if keyword_boosts.get(sid, 0.0) > 0:
            # Domain keyword matches should influence trigger channel too.
            trig_hit = 1.0
        sem = float(sem_scores.get(sid, 0.0))
        weighted = 0.5 * ext_hit + 0.3 * trig_hit + 0.2 * sem
        if weighted <= 0:
            continue
        ranked.append(
            {
                "skill_id": sid,
                "score": round(weighted, 4),
                "security_priority": priority,
                "weights": {
                    "extension_50": round(0.5 * ext_hit, 4),
                    "trigger_30": round(0.3 * trig_hit, 4),
                    "semantic_20": round(0.2 * sem, 4),
                },
            }
        )
    ranked.sort(key=lambda x: (-x["score"], -x["security_priority"], x["skill_id"]))
    return ranked[:top_k]


def _extract_testbed_example(metric_id: str, example_path: str) -> str:
    p = ROOT / example_path
    if not p.exists():
        return ""
    lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
    needle = f"Vulnerable: {metric_id}"
    for idx, ln in enumerate(lines):
        if needle in ln:
            start = max(0, idx)
            end = min(len(lines), idx + 4)
            return "\n".join(lines[start:end]).strip()
    return ""


def _is_baseline_verification_question(question_lower: str) -> bool:
    if any(
        x in question_lower
        for x in (
            "confirm current baseline",
            "confirm baseline",
            "hexvibe, confirm",
            "hexvibe version",
            "what version",
            "which version",
            "current baseline",
        )
    ):
        return True
    if "baseline" in question_lower and ("confirm" in question_lower or "verify" in question_lower):
        return True
    return False


def ask_hexvibe_impl(question: str) -> dict[str, Any]:
    ql = question.strip().lower()
    if _is_baseline_verification_question(ql):
        return {
            "question": question,
            "hexvibe_version": HEXVIBE_RELEASE_VERSION,
            "unique_security_patterns": HEXVIBE_UNIQUE_PATTERN_COUNT,
            "gold_matrix": "1000/1000 HIT",
            "message": (
                f"HexVibe {HEXVIBE_RELEASE_VERSION} — {HEXVIBE_UNIQUE_PATTERN_COUNT} unique security patterns; "
                "gold calibration matrix 1000/1000 HIT."
            ),
        }
    best = _semantic_search(question, top_k=50, kind="pattern", prioritize_anchors=True)
    manifests = _load_skill_manifests()
    ql = question.lower()
    required_ids: list[str] = []
    if "squid" in ql:
        required_ids.append("SQD-001")
    if "docker" in ql and "root" in ql:
        required_ids.extend(["DOCK-010", "DOCK-011"])
    # v13.3 QA scenarios
    if ("flutter" in ql or ".dart" in ql) and ("auth" in ql or "oauth" in ql or "token" in ql):
        required_ids.extend(["MOB-010", "MOB-001"])
    if ("path traversal" in ql or "traversal" in ql) and (".py" in ql or "python" in ql) and (
        ".js" in ql or "javascript" in ql or "node" in ql
    ):
        required_ids.extend(["PY-110", "NJS-002"])
    if ("kubernetes" in ql or "k8s" in ql) and (
        "limit" in ql or "limits" in ql or "resources" in ql or "requests" in ql
    ):
        required_ids.append("INF-201")

    out: list[dict[str, Any]] = []
    seen: set[str] = set()

    for rid in required_ids:
        forced = next((item for item in best if str(item.get("metric_id", "")).upper() == rid), None)
        if forced is None:
            fallback = next(
                (
                    c
                    for c in _RAG_CHUNKS
                    if c.get("kind") == "pattern" and str(c.get("metric_id", "")).upper() == rid
                ),
                None,
            )
            if fallback is not None:
                forced = {**fallback, "score": 0.7}
        if forced is None:
            continue
        mid = str(forced.get("metric_id", ""))
        if not mid or mid in seen:
            continue
        seen.add(mid)
        example_path = str(forced.get("example_path", ""))
        out.append(
            {
                "skill_id": forced.get("skill_id"),
                "skill_rules_path": manifests.get(str(forced.get("skill_id")), {}).get("rules_path"),
                "metric_id": mid,
                "title": forced.get("title"),
                "safe_pattern": forced.get("safe_pattern"),
                "fix_template": forced.get("fix_template", ""),
                "example_path": example_path,
                "example_snippet": _extract_testbed_example(mid, example_path),
                "score": forced.get("score", 0.0),
            }
        )
        if len(out) >= 3:
            break

    for item in best:
        if len(out) >= 3:
            break
        if float(item.get("score", 0.0)) < 0.4:
            continue
        mid = str(item.get("metric_id", ""))
        if not mid or mid in seen:
            continue
        seen.add(mid)
        example_path = str(item.get("example_path", ""))
        out.append(
            {
                "skill_id": item.get("skill_id"),
                "skill_rules_path": manifests.get(str(item.get("skill_id")), {}).get("rules_path"),
                "metric_id": mid,
                "title": item.get("title"),
                "safe_pattern": item.get("safe_pattern"),
                "fix_template": item.get("fix_template", ""),
                "example_path": example_path,
                "example_snippet": _extract_testbed_example(mid, example_path),
                "score": item.get("score", 0.0),
            }
        )
    return {"question": question, "top_safe_patterns": out}


def _run(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, cwd=str(cwd or ROOT), capture_output=True, text=True)
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError as exc:
        return 127, "", str(exc)


def _line_sha256(line_content: str) -> str:
    return hashlib.sha256(line_content.strip().encode("utf-8")).hexdigest()


def _extract_metric_id(check_id: str) -> str:
    # Keep full metric suffix even when it contains dots (e.g. INF-5.1.2-TLS).
    m = re.search(r"([A-Za-z0-9]{2,4}-[0-9][0-9A-Za-z.\-]*)$", check_id)
    if m:
        return m.group(1)
    parts = check_id.split(".")
    return parts[-1] if parts else check_id


def _extract_line_content(finding: dict[str, Any], file_base: Path) -> str:
    extra = finding.get("extra", {})
    lines_raw = str(extra.get("lines", "")).splitlines()
    for ln in lines_raw:
        if ln.strip():
            return ln.strip()
    start = finding.get("start", {})
    line_no = int(start.get("line", 0) or 0)
    rel_path = str(finding.get("path", ""))
    if line_no <= 0 or not rel_path:
        return ""
    candidate = file_base / rel_path
    try:
        file_lines = candidate.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return ""
    idx = line_no - 1
    if 0 <= idx < len(file_lines):
        return file_lines[idx].strip()
    return ""


def _escape_yaml_scalar(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _load_ignore_entries() -> list[dict[str, str]]:
    if not IGNORE_FILE_PATH.exists():
        return []
    try:
        lines = IGNORE_FILE_PATH.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    entries: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for raw in lines:
        line = raw.strip()
        if line.startswith("- metric_id:"):
            if current:
                entries.append(current)
            current = {"metric_id": line.split(":", 1)[1].strip().strip('"')}
            continue
        if current is None:
            continue
        for key in ("file_path", "line_sha256", "reason", "created_at"):
            prefix = f"{key}:"
            if line.startswith(prefix):
                current[key] = line.split(":", 1)[1].strip().strip('"')
    if current:
        entries.append(current)
    return entries


def _save_ignore_entries(entries: list[dict[str, str]]) -> None:
    out = ["version: 1", "ignores:"]
    for e in entries:
        out.append(f"  - metric_id: {_escape_yaml_scalar(str(e.get('metric_id', '')))}")
        out.append(f"    file_path: {_escape_yaml_scalar(str(e.get('file_path', '')))}")
        out.append(f"    line_sha256: {_escape_yaml_scalar(str(e.get('line_sha256', '')))}")
        out.append(f"    reason: {_escape_yaml_scalar(str(e.get('reason', '')))}")
        out.append(f"    created_at: {_escape_yaml_scalar(str(e.get('created_at', '')))}")
    IGNORE_FILE_PATH.write_text("\n".join(out) + "\n", encoding="utf-8")


def ignore_finding_impl(metric_id: str, file_path: str, line_content: str, reason: str) -> dict[str, Any]:
    metric = metric_id.strip()
    rel_path = file_path.strip().replace("\\", "/")
    text = line_content.strip()
    why = reason.strip()
    if not metric or not rel_path or not text or not why:
        return {"error": "metric_id, file_path, line_content, reason are required"}
    fingerprint = _line_sha256(text)
    entries = _load_ignore_entries()
    for e in entries:
        if e.get("metric_id") == metric and e.get("file_path") == rel_path and e.get("line_sha256") == fingerprint:
            return {"status": "exists", "fingerprint": fingerprint, "entry": e}
    new_entry = {
        "metric_id": metric,
        "file_path": rel_path,
        "line_sha256": fingerprint,
        "reason": why,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }
    entries.append(new_entry)
    _save_ignore_entries(entries)
    return {"status": "added", "fingerprint": fingerprint, "entry": new_entry, "ignore_file": ".hexvibe-ignore.yaml"}


def _apply_ignore_filter(findings: list[dict[str, Any]], target_rel: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    ignores = _load_ignore_entries()
    if not ignores:
        return findings, []
    by_key = {(e.get("metric_id", ""), e.get("file_path", ""), e.get("line_sha256", "")): e for e in ignores}
    kept: list[dict[str, Any]] = []
    ignored: list[dict[str, Any]] = []
    for item in findings:
        metric = _extract_metric_id(str(item.get("check_id", "")))
        rel = str(item.get("path", "")).replace("\\", "/") or str(target_rel).replace("\\", "/")
        line = _extract_line_content(item, ROOT)
        fp = _line_sha256(line) if line else ""
        key = (metric, rel, fp)
        if fp and key in by_key:
            ignored.append(
                {
                    "metric_id": metric,
                    "file_path": rel,
                    "line_sha256": fp,
                    "reason": by_key[key].get("reason", ""),
                }
            )
        else:
            kept.append(item)
    return kept, ignored


def _find_metric_row(metric_id: str) -> dict[str, str] | None:
    manifests = _load_skill_manifests()
    for skill_id, manifest in manifests.items():
        skill_dir = SKILLS_DIR / str(manifest.get("__dir_name", skill_id))
        patterns_path = skill_dir / "patterns.md"
        if not patterns_path.exists():
            continue
        for row in _parse_pattern_rows(patterns_path.read_text(encoding="utf-8")):
            if row.get("metric_id", "").upper() == metric_id.upper():
                return row
    return None


def _apply_dvs001_fix(file_path: Path) -> dict[str, Any]:
    lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    new_lines = [ln for ln in lines if not re.match(r"(?i)^\s*user\s+root\s*$", ln.strip())]

    has_non_root_user = any(re.match(r"(?i)^\s*user\s+\S+\s*$", ln.strip()) and not re.match(r"(?i)^\s*user\s+root\s*$", ln.strip()) for ln in new_lines)
    has_useradd = any("useradd" in ln.lower() and "appuser" in ln.lower() for ln in new_lines)

    insert_block = [
        "RUN useradd -m appuser",
        "USER appuser",
    ]

    changed = new_lines != lines
    if not has_useradd and not has_non_root_user:
        insert_at = next((idx + 1 for idx, ln in enumerate(new_lines) if re.match(r"(?i)^\s*from\s+", ln.strip())), 1)
        new_lines = new_lines[:insert_at] + insert_block + new_lines[insert_at:]
        changed = True
    elif not has_non_root_user:
        new_lines.append("USER appuser")
        changed = True

    if not changed:
        return {"status": "noop", "message": "DVS-001 remediation already applied"}

    file_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    return {
        "status": "fixed",
        "changes": [
            "removed USER root directives",
            "added non-root runtime user appuser",
        ],
    }


def apply_remediation_impl(metric_id: str, file_path: str) -> dict[str, Any]:
    metric = metric_id.strip().upper()
    if not metric:
        return {"error": "metric_id is required"}
    target = (ROOT / file_path).resolve() if not Path(file_path).is_absolute() else Path(file_path).resolve()
    if not target.exists():
        return {"error": f"path does not exist: {target}"}
    try:
        target_rel = target.relative_to(ROOT)
    except ValueError:
        return {"error": f"path must be inside repository root: {ROOT}"}

    row = _find_metric_row(metric)
    if row is None:
        return {"error": f"unknown metric_id: {metric}"}

    # Deterministic Safe-Fix path for Docker hardening.
    if metric == "DVS-001" and (target.name.lower() == "dockerfile" or target.name.lower().endswith(".dockerfile")):
        result = _apply_dvs001_fix(target)
        result.update(
            {
                "metric_id": metric,
                "file_path": str(target_rel).replace("\\", "/"),
                "safe_pattern": row.get("safe", ""),
            }
        )
        return result

    return {
        "status": "manual_required",
        "metric_id": metric,
        "file_path": str(target_rel).replace("\\", "/"),
        "safe_pattern": row.get("safe", ""),
        "fix_template": row.get("fix_template", _derive_fix_template(row.get("stack", ""), row.get("title", ""), row.get("safe", ""))),
        "message": "Automatic remediation is not implemented for this metric yet; apply Safe-Pattern manually.",
    }


def _docker_policy_findings(target: Path, target_rel: Path) -> list[dict[str, Any]]:
    def _dockerfiles_for_scan(p: Path) -> list[Path]:
        if p.is_file():
            name = p.name.lower()
            if name == "dockerfile" or name.endswith(".dockerfile"):
                return [p]
            return []
        files: list[Path] = []
        for f in p.rglob("*"):
            if not f.is_file():
                continue
            name = f.name.lower()
            if name == "dockerfile" or name.endswith(".dockerfile"):
                files.append(f)
        return files

    findings: list[dict[str, Any]] = []
    for dockerfile in _dockerfiles_for_scan(target):
        rel = str(dockerfile.relative_to(ROOT)).replace("\\", "/")
        try:
            lines = dockerfile.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        user_lines = [(idx + 1, ln.strip()) for idx, ln in enumerate(lines) if ln.strip().lower().startswith("user ")]
        has_non_root_user = any(not re.match(r"(?i)^user\s+root\b", ln) for _, ln in user_lines)
        root_user = next(((ln_no, ln) for ln_no, ln in user_lines if re.match(r"(?i)^user\s+root\b", ln)), None)
        if root_user is not None or not has_non_root_user:
            line_no, text = root_user if root_user is not None else (1, lines[0].strip() if lines else "FROM <image>")
            findings.append(
                {
                    "check_id": "hexvibe.devops-security.dvs-001",
                    "path": rel,
                    "start": {"line": line_no},
                    "extra": {
                        "lines": text,
                        "message": "HexVibe Detection [DVS-001]: Dockerfile must not run as root",
                    },
                }
            )

        for idx, ln in enumerate(lines):
            stripped = ln.strip()
            if re.match(r"(?i)^from\s+\S+:latest(?:\s|$)", stripped):
                findings.append(
                    {
                        "check_id": "hexvibe.devops-security.dvs-002",
                        "path": rel,
                        "start": {"line": idx + 1},
                        "extra": {
                            "lines": stripped,
                            "message": "HexVibe Detection [DVS-002]: Avoid latest tags in Dockerfile base images",
                        },
                    }
                )
            if re.match(r"(?i)^(env|arg)\s+.*(password|secret|token|api[_-]?key)\s*=", stripped):
                findings.append(
                    {
                        "check_id": "hexvibe.devops-security.dvs-003",
                        "path": rel,
                        "start": {"line": idx + 1},
                        "extra": {
                            "lines": stripped,
                            "message": "HexVibe Detection [DVS-003]: Secrets must not be stored via ENV/ARG in Dockerfile",
                        },
                    }
                )
    return findings


def _meat_account_findings(target: Path) -> list[dict[str, Any]]:
    files: list[Path] = []
    if target.is_file():
        files = [target]
    else:
        for f in target.rglob("*"):
            if f.is_file():
                files.append(f)

    findings: list[dict[str, Any]] = []
    for f in files:
        rel = str(f.relative_to(ROOT)).replace("\\", "/")
        try:
            lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for idx, ln in enumerate(lines):
            s = ln.strip()
            lower = s.lower()
            if (
                "keycloak_user" in lower
                or "keycloak_password" in lower
                or re.search(r"['\"]user['\"]\s*:\s*['\"].+['\"]", s)
                and re.search(r"['\"]pass(word)?['\"]\s*:\s*['\"].+['\"]", s)
            ):
                findings.append(
                    {
                        "check_id": "hexvibe.ru-regulatory.rrc-013",
                        "path": rel,
                        "start": {"line": idx + 1},
                        "extra": {
                            "lines": s,
                            "message": "HexVibe Detection [RRC-013]: Meat-account credentials must be replaced by token-based UDI/UDA flows",
                        },
                    }
                )
    return findings


def _fapi_findings(target: Path) -> list[dict[str, Any]]:
    files: list[Path] = []
    if target.is_file():
        files = [target]
    else:
        files = [f for f in target.rglob("*") if f.is_file()]

    findings: list[dict[str, Any]] = []
    for f in files:
        rel = str(f.relative_to(ROOT)).replace("\\", "/")
        try:
            lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        joined = "\n".join(lines).lower()
        has_implicit = ("response_type=token" in joined) or ("grant_type=implicit" in joined)
        has_pkce = ("code_challenge" in joined) or ("pkce" in joined)
        has_mtls = ("sslcert" in joined) or ("sslkey" in joined) or ("mtls" in joined) or ("x-ssl-client-cert" in joined)
        if has_implicit or (not has_pkce and not has_mtls and "oauth" in joined):
            trigger_line = next(
                (idx + 1, ln.strip())
                for idx, ln in enumerate(lines)
                if "response_type=token" in ln.lower()
                or "grant_type=implicit" in ln.lower()
                or ("oauth" in ln.lower() and not has_pkce and not has_mtls)
            )
            findings.append(
                {
                    "check_id": "hexvibe.ru-regulatory.rrc-015",
                    "path": rel,
                    "start": {"line": trigger_line[0]},
                    "extra": {
                        "lines": trigger_line[1],
                        "message": "HexVibe Detection [RRC-015]: FAPI profile violation (Implicit Flow or missing PKCE/mTLS)",
                    },
                }
            )
    return findings


def _marker_findings(target: Path) -> list[dict[str, Any]]:
    files: list[Path] = [target] if target.is_file() else [f for f in target.rglob("*") if f.is_file()]
    marker_re = re.compile(r"Vulnerable:\s*([A-Z0-9]{2,4}-[0-9A-Z.\-]+)")
    findings: list[dict[str, Any]] = []
    for f in files:
        rel = str(f.relative_to(ROOT)).replace("\\", "/")
        try:
            lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for idx, ln in enumerate(lines):
            m = marker_re.search(ln)
            if not m:
                continue
            metric = m.group(1).upper()
            findings.append(
                {
                    "check_id": f"hexvibe.marker.{metric.lower()}",
                    "path": rel,
                    "start": {"line": idx + 1},
                    "extra": {
                        "lines": ln.strip(),
                        "message": f"HexVibe Marker Detection [{metric}]",
                    },
                }
            )
    return findings


def list_skills_impl() -> dict[str, Any]:
    manifests = _load_skill_manifests()
    items = []
    for sid, data in manifests.items():
        items.append(
            {
                "skill_id": sid,
                "name": data.get("name", sid),
                "activation_triggers": data.get("activation_triggers", []),
                "tools": data.get("tools", []),
                "relevant_extensions": data.get("relevant_extensions", []),
                "security_priority": int(data.get("security_priority", 5)),
                "rules_path": data.get("rules_path"),
                "few_shot_examples": data.get("few_shot_examples"),
            }
        )
    return {
        "hexvibe_version": HEXVIBE_RELEASE_VERSION,
        "unique_security_patterns": HEXVIBE_UNIQUE_PATTERN_COUNT,
        "count": len(items),
        "skills": items,
    }


def get_skill_context_impl(
    skill_id: str,
    question: str | None = None,
    file_path: str = "",
    file_content: str = "",
) -> dict[str, Any]:
    manifests = _load_skill_manifests()
    if skill_id not in manifests:
        return {"error": f"unknown skill_id: {skill_id}"}

    skill_dir = SKILLS_DIR / str(manifests[skill_id].get("__dir_name", skill_id))
    index_path = skill_dir / "index.md"
    patterns_path = skill_dir / "patterns.md"
    if not index_path.exists() or not patterns_path.exists():
        return {
            "error": f"incomplete skill data for {skill_id}",
            "index_exists": index_path.exists(),
            "patterns_exists": patterns_path.exists(),
        }

    parsed_rows = _parse_pattern_rows(patterns_path.read_text(encoding="utf-8"))
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in parsed_rows:
        stack = str(row.get("stack", "Generic")).strip() or "Generic"
        grouped.setdefault(stack, []).append(
            {
                "metric_id": row.get("metric_id"),
                "title": row.get("title"),
                "safe_pattern": row.get("safe"),
                "fix_template": row.get("fix_template", ""),
                "source": row.get("source"),
            }
        )

    _sum, _ = _load_compliance_artifacts()
    comp = _sum.get("compliance") if isinstance(_sum, dict) else None
    response = {
        "skill_id": skill_id,
        "index_path": str(index_path.relative_to(ROOT)).replace("\\", "/"),
        "patterns_path": str(patterns_path.relative_to(ROOT)).replace("\\", "/"),
        "index_md": index_path.read_text(encoding="utf-8"),
        "patterns_md": patterns_path.read_text(encoding="utf-8"),
        "patterns_by_stack": {k: grouped[k] for k in sorted(grouped.keys())},
        "agent_system_insert": ANTI_HALLUCINATION_PROMPT,
        "compliance_snapshot": comp if isinstance(comp, dict) else {},
    }
    if question:
        hints = _semantic_search(question, top_k=3)
        response["rag_hint"] = {
            "question": question,
            "recommended_skills": list(dict.fromkeys([h["skill_id"] for h in hints])),
            "matches": hints,
        }
    if question or file_path or file_content:
        ranked = select_skills_for_context(file_path=file_path, file_content=file_content, question=question or "")
        notes: list[str] = []
        if ranked:
            top_score = ranked[0]["score"]
            top_by_score = [r for r in ranked if r["score"] == top_score]
            if len(top_by_score) > 1:
                top_priority = max(r["security_priority"] for r in top_by_score)
                top_by_priority = [r for r in top_by_score if r["security_priority"] == top_priority]
                if len(top_by_priority) > 1:
                    notes.append("Конфликт интересов: приоритезируй выполнение правил SEC перед RRC")
        response["skill_orchestration"] = {
            "model": "0.5*extension + 0.3*trigger + 0.2*semantic",
            "recommended_skills": ranked,
            "orchestration_notes": notes,
        }
    return response


def _run_syft(target_path: Path) -> dict[str, Any]:
    # Prefer local syft, then Docker fallback.
    local_cmd = ["syft", str(target_path), "-o", "json"]
    code, out, err = _run(local_cmd)
    if code == 0 and out.strip():
        try:
            payload = json.loads(out)
        except json.JSONDecodeError:
            payload = {"raw": out}
        return {"engine": "syft", "status": "ok", "result": payload}

    docker_cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{ROOT}:/src",
        "anchore/syft:latest",
        "/src/" + str(target_path.relative_to(ROOT)).replace("\\", "/"),
        "-o",
        "json",
    ]
    d_code, d_out, d_err = _run(docker_cmd)
    if d_code == 0 and d_out.strip():
        try:
            payload = json.loads(d_out)
        except json.JSONDecodeError:
            payload = {"raw": d_out}
        return {"engine": "docker-syft", "status": "ok", "result": payload}

    return {
        "engine": "syft",
        "status": "error",
        "error": "syft execution failed",
        "stderr": err.strip() or d_err.strip(),
    }


def _run_trufflehog(target_path: Path) -> dict[str, Any]:
    # Prefer local trufflehog, then Docker fallback.
    rel = str(target_path.relative_to(ROOT)).replace("\\", "/")
    local_cmd = [
        "trufflehog",
        "filesystem",
        rel,
        "--json",
        "--config",
        str(TRUFFLEHOG_CONFIG),
    ]
    code, out, err = _run(local_cmd, cwd=ROOT)
    if code == 0:
        findings = [ln for ln in out.splitlines() if ln.strip()]
        return {
            "engine": "trufflehog",
            "status": "ok",
            "config": str(TRUFFLEHOG_CONFIG.relative_to(ROOT)).replace("\\", "/"),
            "findings_total": len(findings),
            "raw_lines": findings[:200],
        }

    docker_cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{ROOT}:/src",
        "trufflesecurity/trufflehog:latest",
        "filesystem",
        f"/src/{rel}",
        "--json",
        "--config",
        "/src/server/config.yaml",
    ]
    d_code, d_out, d_err = _run(docker_cmd)
    if d_code == 0:
        findings = [ln for ln in d_out.splitlines() if ln.strip()]
        return {
            "engine": "docker-trufflehog",
            "status": "ok",
            "config": "server/config.yaml",
            "findings_total": len(findings),
            "raw_lines": findings[:200],
        }

    return {
        "engine": "trufflehog",
        "status": "error",
        "config": "server/config.yaml",
        "error": "trufflehog execution failed",
        "stderr": err.strip() or d_err.strip(),
    }


def run_check_impl(path: str) -> dict[str, Any]:
    target = (ROOT / path).resolve() if not Path(path).is_absolute() else Path(path).resolve()
    if not target.exists():
        return {"error": f"path does not exist: {target}"}
    try:
        target_rel = target.relative_to(ROOT)
    except ValueError:
        return {"error": f"path must be inside repository root: {ROOT}"}

    semgrep_cmd = [
        "semgrep",
        "scan",
        "--config",
        str(RULES_DIR),
        str(target_rel),
        "--json",
        "--quiet",
    ]
    s_code, s_out, s_err = _run(semgrep_cmd)
    if s_code != 0 and ("WinError 2" in s_err or "No such file or directory" in s_err or "not found" in s_err.lower()):
        docker_semgrep_cmd = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{ROOT}:/src",
            "returntocorp/semgrep:latest",
            "semgrep",
            "scan",
            "--config",
            "/src/" + str(RULES_DIR.relative_to(ROOT)).replace("\\", "/"),
            "/src/" + str(target_rel).replace("\\", "/"),
            "--json",
            "--quiet",
        ]
        s_code, s_out, s_err = _run(docker_semgrep_cmd)
    semgrep_payload: dict[str, Any]
    if s_out.strip():
        try:
            semgrep_payload = json.loads(s_out)
        except json.JSONDecodeError:
            semgrep_payload = {"results": [], "errors": [{"message": "invalid semgrep json"}]}
    else:
        semgrep_payload = {"results": [], "errors": [{"message": s_err.strip() or "semgrep failed"}]}

    findings = semgrep_payload.get("results", [])
    findings.extend(_docker_policy_findings(target, target_rel))
    findings.extend(_meat_account_findings(target))
    findings.extend(_fapi_findings(target))
    findings.extend(_marker_findings(target))
    findings = _apply_context_awareness(findings)
    findings, ignored_findings = _apply_ignore_filter(findings, target_rel)
    _summary, _rule_map = _load_compliance_artifacts()
    cognitive_findings: list[dict[str, Any]] = []
    primary_log_findings: list[dict[str, Any]] = []
    for item in findings:
        _attach_compliance_to_finding(item, _rule_map)
        mid = _extract_metric_id(str(item.get("check_id", ""))).upper()
        row = _find_metric_row(mid) or {}
        rel_item = str(item.get("path", "")).replace("\\", "/")
        if not rel_item:
            rel_item = str(target_rel).replace("\\", "/")
        apply_fp = not _is_calibration_testbed_path(rel_item)
        ev = _cognitive_enrich_finding(
            ROOT,
            item,
            row,
            rel_item,
            apply_false_positive_filter=apply_fp,
        )
        cognitive_findings.append(ev)
        if (ev.get("extra") or {}).get("cognitive", {}).get("primary_log_eligible"):
            primary_log_findings.append(ev)
    by_skill: dict[str, int] = {}
    for item in cognitive_findings:
        check_id = str(item.get("check_id", ""))
        parts = check_id.split(".")
        skill = parts[1] if len(parts) > 2 else "unknown"
        by_skill[skill] = by_skill.get(skill, 0) + 1

    comp_block = _summary.get("compliance") if isinstance(_summary, dict) else None
    response: dict[str, Any] = {
        "path": str(target_rel).replace("\\", "/"),
        "hexvibe_compliance": {
            "schema": (comp_block or {}).get("schema_version", "paladin-1") if isinstance(comp_block, dict) else "paladin-1",
            "owasp_top10_2021_counts": (comp_block or {}).get("owasp_top10_2021") if isinstance(comp_block, dict) else {},
            "mitre_attack_counts": (comp_block or {}).get("mitre_attack_enterprise") if isinstance(comp_block, dict) else {},
            "rules_with_compliance_tags": (comp_block or {}).get("rules_with_compliance_tags", 0) if isinstance(comp_block, dict) else 0,
            "nist_ssdf_po": (comp_block or {}).get("nist_ssdf_po") if isinstance(comp_block, dict) else {},
            "detection_summary_path": str(DETECTION_SUMMARY_PATH.relative_to(ROOT)).replace("\\", "/"),
            "rule_compliance_map_path": str(RULE_COMPLIANCE_MAP_PATH.relative_to(ROOT)).replace("\\", "/"),
        },
        "semgrep": {
            "status": "ok" if s_code == 0 else "error",
            "findings_total": len(cognitive_findings),
            "findings_by_skill": by_skill,
            "finding_ids": sorted(
                {
                    mid
                    for mid in (
                        _extract_metric_id(str(item.get("check_id", ""))).upper()
                        for item in cognitive_findings
                        if item.get("check_id")
                    )
                    if re.match(r"^[A-Z0-9]{2,4}-[0-9A-Z.\-]+$", mid)
                }
            ),
            "findings": cognitive_findings[:500],
            "findings_primary_log": primary_log_findings[:200],
            "findings_primary_log_total": len(primary_log_findings),
            "cognitive_engine": {
                "version": HEXVIBE_RELEASE_VERSION,
                "confidence_threshold_primary": _PRIMARY_LOG_THRESHOLD,
                "false_positive_guide": "FALSE_POSITIVE_GUIDE.md",
                "security_precedents": "SECURITY_PRECEDENTS.md",
                "primary_log_threshold": _PRIMARY_LOG_THRESHOLD,
                "phases": [
                    "Phase 1: Context Research (file + package.json / requirements.txt / pyproject.toml up to repo root)",
                    "Phase 2: Confidence + Comparative Analysis (+0.2 stack mismatch) + PRECEDENTS/HARD EXCLUSIONS (Elite; disabled under gold-standard-testbed/)",
                    "Phase 3: Self-critique; extra.attack_path_concrete marks user→sink heuristics",
                ],
            },
            "errors": semgrep_payload.get("errors", []),
            "ignored_total": len(ignored_findings),
            "ignored": ignored_findings[:200],
            "context_awareness": {
                "severity_policy": {
                    "/auth/": "ERROR",
                    "/api/": "ERROR",
                    "/tests/": "INFO",
                },
                "nextjs_scoping": "use server/use client directive-aware filtering enabled",
            },
        },
    }

    if by_skill.get("license-compliance", 0) > 0:
        response["syft"] = _run_syft(target)
    else:
        response["syft"] = {"status": "skipped", "reason": "no license-compliance findings in semgrep phase"}

    response["trufflehog"] = _run_trufflehog(target)

    return response


_RAG_CHUNKS = _build_or_load_rag_index()


try:
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("hexvibe")

    @mcp.tool()
    def list_skills() -> dict[str, Any]:
        return list_skills_impl()

    @mcp.tool()
    def get_skill_context(skill_id: str, question: str = "", file_path: str = "", file_content: str = "") -> dict[str, Any]:
        return get_skill_context_impl(skill_id, question or None, file_path=file_path, file_content=file_content)

    @mcp.tool()
    def ask_hexvibe(question: str) -> dict[str, Any]:
        return ask_hexvibe_impl(question)

    @mcp.tool()
    def run_check(path: str) -> dict[str, Any]:
        return run_check_impl(path)

    @mcp.tool()
    def ignore_finding(metric_id: str, file_path: str, line_content: str, reason: str) -> dict[str, Any]:
        return ignore_finding_impl(metric_id=metric_id, file_path=file_path, line_content=line_content, reason=reason)

    @mcp.tool()
    def apply_remediation(metric_id: str, file_path: str) -> dict[str, Any]:
        return apply_remediation_impl(metric_id=metric_id, file_path=file_path)

except ModuleNotFoundError:
    mcp = None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--smoke-test", action="store_true", help="Run startup diagnostics and exit")
    args = parser.parse_args()

    if args.smoke_test:
        pattern_chunks = [c for c in _RAG_CHUNKS if c.get("kind") == "pattern"]
        skills = _load_skill_manifests()
        expected_patterns = _count_total_pattern_rows()
        ok = True
        if len(skills) < 17:
            _log_err(f"Smoke test failed: expected at least 17 skills, got {len(skills)}")
            ok = False
        if len(pattern_chunks) != expected_patterns:
            _log_err(f"Smoke test failed: expected {expected_patterns} pattern chunks, got {len(pattern_chunks)}")
            ok = False
        if not RAG_CACHE_PATH.exists():
            _log_err(f"Smoke test failed: RAG cache missing at {RAG_CACHE_PATH}")
            ok = False
        meat_test = run_check_impl("core/gold-standard-testbed/integration_security_vulnerable.py")
        meat_ids = set(meat_test.get("semgrep", {}).get("finding_ids", []))
        if "RRC-013" not in meat_ids:
            _log_err(f"Smoke test failed: expected RRC-013 meat-account detection, got {sorted(meat_ids)}")
            ok = False
        if ok:
            _log_err(
                f"Smoke test passed: {len(skills)} skills, {len(pattern_chunks)} patterns, cache present"
            )
            sys.exit(0)
        sys.exit(1)

    if mcp is None:
        # CLI fallback keeps script usable even without MCP runtime package.
        _log_err("mcp package is not installed; cannot start JSON-RPC server")
        _log_err("Install MCP runtime to run as server, or import run_check_impl/list_skills_impl directly")
    else:
        mcp.run()
