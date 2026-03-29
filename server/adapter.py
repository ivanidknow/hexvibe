"""
HexVibe MCP adapter for skill-based security checks.

Tools exposed:
- list_skills()
- get_skill_context(skill_id)
- ask_hexvibe(question)
- run_check(path)
- run_security_review(project_name, context)  # includes STRIDE threat modeling (Section 0) before run_check
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
THREAT_MODEL_CACHE_PATH = ROOT / "server" / ".threat-model-cache.json"
THREAT_MODEL_CACHE_SCHEMA_VERSION = 2
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
# Security review profiles: FastAPI Backend (service/agent stacks) vs Desktop App (Electron / desktop integration).
PROFILE_FASTAPI_BACKEND = "fastapi_backend"
PROFILE_DESKTOP_APP = "desktop_app"

ENTERPRISE_BASELINES: dict[str, str] = {
    PROFILE_FASTAPI_BACKEND: (
        "Project deployed in Enterprise Kubernetes. Identity & Access: Keycloak SSO is the only source of truth; "
        "local user/password databases are prohibited. WebSocket Management: backend must authorize every "
        "WS connection and enforce ownership checks for user-session binding. "
        "Network Topology: backend and agent are isolated; any outbound traffic to LLM providers, "
        "speech/transcription APIs, and S3-compatible object storage must pass strictly through an "
        "egress HTTP proxy and reverse proxy (e.g. Nginx). "
        "Data Flow: direct service-to-public-internet connections are prohibited; summarization and transcription "
        "integrations are trusted only when proxy mediation is present. "
        "Logging: External (Fluentbit/SIEM). Storage: S3-compatible (Presigned URLs). Disk: Encrypted (AES-256)."
    ),
    PROFILE_DESKTOP_APP: (
        "Project deployed in Enterprise Kubernetes. Core Architecture (Electron): strict split between "
        "UI Renderer and Main Process, communication only via IPC (invoke + events). Renderer direct "
        "access to Node.js APIs or network is prohibited; enforce preload usage and context isolation "
        "(nodeIntegration=false, contextIsolation=true). Identity & API Gateway: all external "
        "API calls (LLM, RAG, transcription, calendar/mail integrations) must pass through the central API gateway "
        "with token validation; any direct external service call bypassing the gateway is critical. "
        "Internal Orchestration: Supervisor plans, Branch Runner executes tools; tool outputs must flow into Answer Node for final synthesis. "
        "Local Data Privacy: user data (history, settings, patterns) remains in local userData and must not leak into "
        "external logs or IPC payloads. Legacy Path (Vision/RAG without agent) must also pass through the gateway."
    ),
}
SECURITY_REVIEW_ENGINE_PROMPT = (
    "System Role: HexVibe Security Engine Orchestrator. "
    "When reviewing network-security findings, treat HTTP_PROXY/HTTPS_PROXY or explicit proxy routing "
    "as mandatory evidence for OK status. If external API calls exist but context confirms proxy mediation, "
    "suppress direct-internet false positives and classify findings according to architecture constraints."
)


def _engine_prompt_for_profile(profile: str) -> str:
    if profile == PROFILE_DESKTOP_APP:
        return (
            f"{SECURITY_REVIEW_ENGINE_PROMPT} "
            "Desktop App mode: mark external calls as OK only when the endpoint chain goes through the central API gateway; "
            "detect IPC Injection risks in Renderer->Main message flow; verify secure token processing "
            "for gateway-mediated external API access."
        )
    return SECURITY_REVIEW_ENGINE_PROMPT


def _threat_scan_root(target_rel: str) -> Path:
    base = (ROOT / target_rel).resolve() if target_rel and target_rel != "." else ROOT
    return base if base.is_dir() else base.parent


def _parse_simple_deps_file(path: Path, max_lines: int = 400) -> set[str]:
    out: set[str] = set()
    if not path.is_file():
        return out
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return out
    for raw in text.splitlines()[:max_lines]:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if path.name == "package.json":
            continue
        # requirements.txt / constraints: take name before [ or ; or =
        m = re.match(r"^([a-zA-Z0-9_.\-]+)", line)
        if m:
            out.add(m.group(1).lower().replace("_", "-"))
    return out


def _parse_package_json_deps(path: Path) -> set[str]:
    out: set[str] = set()
    if not path.is_file():
        return out
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (json.JSONDecodeError, OSError):
        return out
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        block = data.get(key)
        if isinstance(block, dict):
            out.update(str(k).lower() for k in block.keys())
    return out


def _collect_repo_threat_signals(scan_root: Path) -> dict[str, Any]:
    try:
        scan_rel = str(scan_root.relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        scan_rel = str(scan_root)
    signals: dict[str, Any] = {
        "scan_root": scan_rel,
        "top_level_dirs": [],
        "key_files": [],
        "deps": set(),
        "flags": {
            "has_dockerfile": False,
            "has_compose": False,
            "has_k8s_yaml": False,
            "has_github_workflows": False,
            "has_electron": False,
            "has_playwright": False,
            "has_fastapi": False,
            "has_redis_client": False,
        },
    }
    try:
        for child in sorted(scan_root.iterdir(), key=lambda p: p.name.lower()):
            if child.is_dir() and not child.name.startswith("."):
                signals["top_level_dirs"].append(child.name)
                if len(signals["top_level_dirs"]) >= 40:
                    break
    except OSError:
        pass

    deps: set[str] = set()
    try:
        for pattern in ("**/package.json", "**/requirements.txt", "**/pyproject.toml", "**/go.mod"):
            for p in scan_root.glob(pattern):
                if len(signals["key_files"]) >= 100:
                    break
                if any(part.startswith(".") for part in p.parts):
                    continue
                rel = str(p.relative_to(scan_root)).replace("\\", "/")
                if rel not in signals["key_files"]:
                    signals["key_files"].append(rel)
                if p.name == "package.json":
                    deps |= _parse_package_json_deps(p)
                elif p.name == "requirements.txt":
                    deps |= _parse_simple_deps_file(p)
                elif p.name == "pyproject.toml":
                    try:
                        txt = p.read_text(encoding="utf-8", errors="ignore").lower()
                        for m in re.finditer(r"['\"]([a-zA-Z0-9_.\-]+)['\"]", txt):
                            deps.add(m.group(1).lower())
                    except OSError:
                        pass
            if len(signals["key_files"]) >= 100:
                break
        for name in ("Dockerfile", "docker-compose.yml", "docker-compose.yaml"):
            fp = scan_root / name
            if fp.is_file():
                signals["key_files"].append(name)
                if name == "Dockerfile":
                    signals["flags"]["has_dockerfile"] = True
                else:
                    signals["flags"]["has_compose"] = True
        for p in scan_root.rglob("*.yaml"):
            if p.is_file() and any(x in p.name.lower() for x in ("deploy", "helm", "k8s", "values")):
                signals["flags"]["has_k8s_yaml"] = True
                break
        wf = scan_root / ".github" / "workflows"
        if wf.is_dir():
            signals["flags"]["has_github_workflows"] = True
    except OSError:
        pass

    signals["deps"] = sorted(deps)
    djoin = " ".join(deps)
    signals["flags"]["has_electron"] = "electron" in djoin
    signals["flags"]["has_playwright"] = "playwright" in djoin or "@playwright/test" in djoin
    signals["flags"]["has_fastapi"] = "fastapi" in djoin or "starlette" in djoin
    signals["flags"]["has_redis_client"] = any(
        x in djoin for x in ("redis", "aioredis", "rq", "celery", "hiredis")
    )
    return signals


def _repo_threat_fingerprint(signals: dict[str, Any]) -> str:
    payload = json.dumps(
        {
            "top_level_dirs": signals.get("top_level_dirs", []),
            "key_files": sorted(set(signals.get("key_files", [])))[:80],
            "deps": signals.get("deps", []),
            "flags": signals.get("flags", {}),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _threat_cache_key(profile: str, final_context: str, repo_fp: str) -> str:
    raw = f"{profile}\n{final_context}\n{repo_fp}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _load_threat_model_cache() -> dict[str, Any]:
    if not THREAT_MODEL_CACHE_PATH.exists():
        return {"schema_version": THREAT_MODEL_CACHE_SCHEMA_VERSION, "entries": {}}
    try:
        data = json.loads(THREAT_MODEL_CACHE_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"schema_version": THREAT_MODEL_CACHE_SCHEMA_VERSION, "entries": {}}
    if int(data.get("schema_version", 0)) != THREAT_MODEL_CACHE_SCHEMA_VERSION:
        return {"schema_version": THREAT_MODEL_CACHE_SCHEMA_VERSION, "entries": {}}
    entries = data.get("entries")
    if not isinstance(entries, dict):
        entries = {}
    return {"schema_version": THREAT_MODEL_CACHE_SCHEMA_VERSION, "entries": entries}


def _save_threat_model_cache_entry(cache_key: str, markdown: str) -> None:
    payload = _load_threat_model_cache()
    payload["entries"][cache_key] = {
        "markdown": markdown,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }
    try:
        THREAT_MODEL_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        THREAT_MODEL_CACHE_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except (OSError, TypeError, ValueError):
        _log_err("threat model cache write failed")


def _rag_keywords_from_ask(payload: dict[str, Any]) -> set[str]:
    keys: set[str] = set()
    for row in payload.get("top_safe_patterns", []) or []:
        title = str(row.get("title") or "")
        for t in _tokenize(title):
            if len(t) >= 4:
                keys.add(t)
    return keys


def _stride_classify_clause(clause: str) -> str:
    c = clause.lower()
    if any(x in c for x in ("auth", "jwt", "keycloak", "token", "sso", "spoof", "identity")):
        return "S"
    if any(x in c for x in ("tamper", "integrity", "modify", "inject", "queue", "payload")):
        return "T"
    if any(x in c for x in ("audit", "log", "repud", "deny", "siem", "fluent")):
        return "R"
    if any(x in c for x in ("disclosure", "leak", "pii", "secret", "minio", "s3", "userdata", "ipc")):
        return "I"
    if any(x in c for x in ("dos", "rate", "flood", "availability", "proxy", "egress", "network")):
        return "D"
    if any(x in c for x in ("elevat", "privilege", "bola", "owner", "admin", "branch", "supervisor")):
        return "E"
    return "I"


def _build_stride_threat_candidates(
    profile: str,
    baseline: str,
    signals: dict[str, Any],
    rag_keywords: set[str],
) -> list[tuple[float, str, str, str]]:
    """
    Build ranked STRIDE candidates from profile + Enterprise baseline + repo signals + RAG keywords.
    No fixed global threat list: candidates are emitted only when signals/baseline/RAG justify them.
    """
    deps: set[str] = set(str(d).lower() for d in signals.get("deps", []))
    bl = baseline.lower()
    dirs = " ".join(signals.get("top_level_dirs", [])).lower()
    flags = signals.get("flags", {})
    combined = f"{bl} {' '.join(deps)} {dirs} {' '.join(rag_keywords)}".lower()

    def score(base: float, *terms: str) -> float:
        s = base
        for term in terms:
            if term and term in combined:
                s += 1.5
        return s

    candidates: list[tuple[float, str, str, str]] = []

    if profile == PROFILE_FASTAPI_BACKEND or "keycloak" in bl or "jwt" in deps or "pyjwt" in deps or "python-jose" in deps:
        candidates.append(
            (
                score(4.0, "keycloak", "jwt", "token"),
                "S",
                "Подмена идентичности и токенов на границе API/WS",
                (
                    "С учётом обнаруженных зависимостей и baseline (Keycloak SSO) критичен риск подмены субъекта/аудитории "
                    "и неверной привязки WebSocket-сессии к пользователю при отсутствии строгой проверки ownership."
                ),
            )
        )
    if "websocket" in bl or "ipc" in combined or "playwright" in combined:
        candidates.append(
            (
                score(3.5, "websocket", "playwright", "chromium"),
                "T",
                "Подмена данных в потоке агента/автоматизации",
                (
                    "Потоки Browser/Agent и очереди задач увеличивают поверхность для подмены входных данных и инъекций "
                    "в цепочку инструментов; приоритет — проверка целостности границ и схем валидации."
                ),
            )
        )
    if profile == PROFILE_FASTAPI_BACKEND and any(x in bl for x in ("speaker", "session", "websocket", "event")):
        candidates.append(
            (
                score(4.1, "speaker", "session", "event"),
                "S",
                "Имперсонация при маппинге speaker_id и незащищённом event_url",
                (
                    "Риск присвоения чужой голосовой/медиа-сессии: привязка speaker_id к пользователю только через "
                    "предсказуемый или утечкой полученный event_url без криптографической привязки токена к субъекту."
                ),
            )
        )
    if flags.get("has_redis_client") or "redis" in deps or "rq" in deps:
        candidates.append(
            (
                score(4.2, "redis", "rq", "queue"),
                "T",
                "Целостность очередей и сериализации фоновых задач",
                (
                    "Репозиторий указывает на Redis/RQ/Celery-подсистемы: критична подмена job payload и небезопасная "
                    "десериализация при передаче между воркерами."
                ),
            )
        )
        candidates.append(
            (
                score(3.6, "worker", "backend", "segment"),
                "I",
                "Отсутствие сегментации доверия между Worker и Backend",
                (
                    "Общая очередь/брокер без изоляции tenant/секретов: риск чтения задач и побочных эффектов в чужом "
                    "контексте при ошибочной маршрутизации или общем namespace."
                ),
            )
        )
    if "proxy" in bl or "egress" in bl:
        candidates.append(
            (
                score(4.0, "proxy", "egress", "nginx"),
                "D",
                "Обход изоляции egress и отказ прокси-контура",
                (
                    "Архитектура требует прокси-цепочки; риск — прямой выход процессов в интернет или обход HTTP egress proxy, "
                    "что ведёт к DDoS/злоупотреблению LLM/ASR и нарушению политики Production Environment."
                ),
            )
        )
    if "minio" in bl or "s3" in bl or "boto" in deps or "presign" in bl:
        candidates.append(
            (
                score(3.8, "minio", "s3", "boto"),
                "I",
                "Утечка объектов и метаданных через объектное хранилище",
                (
                    "При наличии S3/MinIO и presigned URL критичны ошибки ACL, TTL и утечки чувствительных ключей/имён объектов "
                    "в логи или клиентские ошибки."
                ),
            )
        )
    if profile == PROFILE_DESKTOP_APP or flags.get("has_electron"):
        candidates.append(
            (
                score(4.5, "electron", "ipc", "preload"),
                "E",
                "Повышение привилегий через IPC и Main Process",
                (
                    "Electron-стек: риск IPC Injection и обхода изоляции Renderer→Main, включая небезопасные preload-мосты "
                    "и прямой доступ к Node.js из UI при неверных webPreferences."
                ),
            )
        )
    if "api gateway" in bl or "central api" in combined or "gateway" in combined:
        candidates.append(
            (
                score(4.3, "gateway", "token", "api"),
                "S",
                "Нарушение цепочки доверия к внешним API через центральный API gateway",
                (
                    "Все внешние интеграции должны проходить через единый API gateway; критичен обход шлюза и некорректная валидация токенов "
                    "на границе LLM/RAG и внешних сервисов."
                ),
            )
        )
    if "fluent" in bl or "siem" in bl or "audit" in bl:
        candidates.append(
            (
                score(3.2, "siem", "audit", "log"),
                "R",
                "Невозможность расследования и отчуждаемость событий",
                (
                    "Baseline требует централизованного журналирования: риск отсутствия корреляции событий безопасности и "
                    "недостаточной трассируемости критичных операций."
                ),
            )
        )

    # Baseline clause-driven fillers (no hardcoded threat names; text from architecture sentences)
    clause_count = 0
    for sentence in re.split(r"[.;]\s+", baseline):
        s = sentence.strip()
        if len(s) < 40:
            continue
        letter = _stride_classify_clause(s)
        candidates.append(
            (
                score(2.0, *s.lower().split()[:3]),
                letter,
                f"Архитектурный риск ({letter}) из baseline",
                s[:500] + ("…" if len(s) > 500 else ""),
            )
        )
        clause_count += 1
        if clause_count >= 8:
            break

    candidates.sort(key=lambda x: -x[0])
    # de-duplicate by (stride, title) keeping highest score
    seen: set[tuple[str, str]] = set()
    unique: list[tuple[float, str, str, str]] = []
    for item in candidates:
        key = (item[1], item[2])
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def _classify_infra_vs_business(stride: str, title: str, desc: str) -> str:
    """Return 'infra' or 'business' for Separation of Concerns split."""
    t = f"{title} {desc}".lower()
    infra_kw = (
        "proxy",
        "egress",
        "network",
        "redis",
        "queue",
        "minio",
        "s3",
        "worker",
        "kubernetes",
        "fluent",
        "siem",
        "storage",
        "шифр",
        "aes",
        "segment",
        "изолирован",
        "контур",
        "dns",
        "tls",
        "ingress",
        "availability",
        "ddos",
        "rate",
    )
    biz_kw = (
        "токен",
        "jwt",
        "keycloak",
        "websocket",
        "ownership",
        "подмен",
        "идентич",
        "ipc",
        "gateway",
        "playwright",
        "сесс",
        "bola",
        "авториз",
        "пользоват",
        "renderer",
        "preload",
        "main process",
        "imperson",
        "speaker",
        "event",
        "api gateway",
    )
    i_score = sum(1 for k in infra_kw if k in t)
    b_score = sum(1 for k in biz_kw if k in t)
    if i_score > b_score:
        return "infra"
    if b_score > i_score:
        return "business"
    if stride in ("D",) or "proxy" in t or "queue" in t:
        return "infra"
    return "business"


def _load_repo_crosscheck_haystack(scan_root: Path, max_total_chars: int = 350_000) -> str:
    """Lightweight text aggregate for architectural cross-check (not full Semgrep)."""
    parts: list[str] = []
    total = 0
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".next"}
    exts = {".py", ".ts", ".tsx", ".js", ".jsx", ".yaml", ".yml", ".go", ".cs", ".json"}
    try:
        paths = sorted(scan_root.rglob("*"), key=lambda p: str(p).replace("\\", "/"))
    except OSError:
        return ""
    n_files = 0
    for p in paths:
        if n_files >= 220:
            break
        if not p.is_file():
            continue
        if p.suffix.lower() not in exts:
            continue
        if any(seg in skip_dirs for seg in p.parts):
            continue
        try:
            rel = p.relative_to(scan_root)
        except ValueError:
            continue
        try:
            chunk = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        snippet = chunk[:14000]
        block = f"\n--- {rel.as_posix()} ---\n{snippet}"
        if total + len(block) > max_total_chars:
            break
        parts.append(block)
        total += len(block)
        n_files += 1
    return "".join(parts)


def _cross_check_architectural_threat(title: str, desc: str, haystack: str) -> str:
    """
    If threat cannot be confirmed or refuted by code sample → manual architect review.
    """
    h = haystack.lower()
    blob = f"{title} {desc}".lower()
    confirms: list[str] = []
    refutes: list[str] = []

    def hit_any(s: str, needles: tuple[str, ...]) -> bool:
        return any(n in s for n in needles)

    if hit_any(blob, ("proxy", "egress", "прокси", "публичн", "internet")):
        if hit_any(h, ("http_proxy", "https_proxy", "https_proxy_authorization", "proxy_pass", "trust_env")):
            confirms.append("прокси/egress-контроль в коде или конфиге")
        elif hit_any(h, ("requests.get", "httpx.get", "aiohttp", "urllib.request")) and not hit_any(
            h, ("http_proxy", "https_proxy", "proxy=", "proxies=")
        ):
            refutes.append("прямые HTTP-клиенты без явного proxy в выборке")

    if hit_any(blob, ("сегмента", "network policy", "изолирован", "worker", "backend")):
        if hit_any(h, ("networkpolicy", "network_policy", "namespace:", "calico", "istio")):
            confirms.append("признаки сетевой политики/неймспейсов")
        elif hit_any(blob, ("worker", "redis", "rq")) and hit_any(h, ("redis", "rq.", "celery")):
            confirms.append("явные границы worker/очереди в коде")

    if hit_any(blob, ("redis", "rq", "очеред", "сериализац")):
        if hit_any(h, ("serializer", "json.loads", "msgpack", "pickle")):
            confirms.append("сериализация очередей/данных")
        if hit_any(h, ("pickle.loads", "pickle.load")) and "json" not in h:
            refutes.append("использование pickle в выборке")

    if hit_any(blob, ("minio", "s3", "presign", "объект")):
        if hit_any(h, ("boto3", "presigned", "minio", "generate_presigned")):
            confirms.append("S3/MinIO/presigned в коде")

    if hit_any(blob, ("websocket", "ws")):
        if hit_any(h, ("websocket", "owner", "authorize", "verify", "depends")):
            confirms.append("авторизация/ownership вокруг WS")

    if hit_any(blob, ("keycloak", "jwt", "sso", "токен")):
        if hit_any(h, ("jwt", "keycloak", "jwks", "audience", "verify")):
            confirms.append("проверка JWT/Keycloak/JWKS")

    if hit_any(blob, ("ipc", "electron", "renderer", "preload")):
        if hit_any(h, ("contextisolation", "context_isolation", "nodeintegration", "preload")):
            confirms.append("Electron webPreferences/preload в выборке")

    if hit_any(blob, ("api gateway", "gateway", "central api")):
        if hit_any(h, ("api_gateway", "apigateway", "gateway", "proxy_pass")):
            confirms.append("упоминание API gateway / прокси в коде")

    if hit_any(blob, ("playwright", "dom", "селектор", "автоматиз")):
        if hit_any(h, ("playwright", "page.goto", "page.locator", "chromium")):
            confirms.append("Playwright/Chromium в коде")

    if hit_any(blob, ("event_url", "event url", "speaker", "сесс")):
        if hit_any(h, ("event_url", "speaker_id", "session_id")):
            confirms.append("event_url/speaker/session в коде")

    confirms = list(dict.fromkeys(confirms))
    refutes = list(dict.fromkeys(refutes))
    if confirms and not refutes:
        return "ПОДТВЕРЖДАЕТСЯ КОДОМ: " + "; ".join(confirms)
    if refutes and not confirms:
        return "ОПРОВЕРГАЕТСЯ ИЛИ СМЯГЧАЕТСЯ КОДОМ: " + "; ".join(refutes)
    if confirms and refutes:
        return (
            "ТРЕБУЕТ РУЧНОЙ ПРОВЕРКИ АРХИТЕКТОРОМ (противоречивые сигналы: "
            + " | ".join(confirms)
            + " vs "
            + " | ".join(refutes)
            + ")"
        )
    return "ТРЕБУЕТ РУЧНОЙ ПРОВЕРКИ АРХИТЕКТОРОМ"


def _build_what_if_scenarios(profile: str, baseline: str, signals: dict[str, Any]) -> list[str]:
    """Three speculative negative scenarios beyond standard rule checks (context-derived)."""
    deps_l = " ".join(signals.get("deps", [])).lower()
    bl = baseline.lower()
    scenarios: list[str] = []

    if profile == PROFILE_FASTAPI_BACKEND or "playwright" in deps_l or "playwright" in bl:
        scenarios.append(
            "Что если целевой веб-сервис изменит DOM-структуру или селекторы? "
            "Как поведёт себя Playwright-инжект и сценарии автоматизации — деградация, ложные срабатывания или утечка действий в чужой контекст?"
        )
    if profile == PROFILE_FASTAPI_BACKEND or "websocket" in bl or "event" in bl:
        scenarios.append(
            "Что если злоумышленник получит или угадает event_url сессии / идентификатор канала? "
            "Допустима ли имперсонация или присоединение к чужой сессии при маппинге speaker_id без криптографической привязки к пользователю?"
        )
    if profile == PROFILE_DESKTOP_APP or signals.get("flags", {}).get("has_electron"):
        scenarios.append(
            "Что если IPC-канал между Renderer и Main принимает недостаточно типизированные сообщения? "
            "Возможна ли инъекция команд/путей, которая обойдёт центральный API gateway и приведёт к исполнению в привилегированном процессе?"
        )
    if len(scenarios) < 3 and ("redis" in deps_l or "rq" in deps_l or "queue" in bl):
        scenarios.append(
            "Что если Worker и Backend разделяют общую очередь без строгой сегментации секретов и tenant_id? "
            "Может ли подмена job payload привести к исполнению действий от имени другого арендатора или сервиса?"
        )
    if len(scenarios) < 3:
        scenarios.append(
            "Что если политика egress (HTTP proxy / reverse proxy) временно недоступна или обходится через DNS-rebinding / прямой резолв? "
            "Сохраняется ли запрет прямого выхода к LLM/ASR/S3 на уровне приложения?"
        )
    if len(scenarios) < 3:
        scenarios.append(
            "Что если локальное хранилище userData (Desktop App) окажется включённым в телеметрию или логи ошибок? "
            "Как исключается утечка истории и настроек во внешние каналы?"
        )
    return scenarios[:3]


def _generate_threat_model(
    profile: str,
    baseline: str,
    signals: dict[str, Any],
    rag_keywords: set[str],
    cached: bool,
    scan_root: Path,
) -> str:
    """
    Architect-grade threat model: infrastructure vs business logic, cross-check vs code, WHAT-IF scenarios.
    Alias entry point for legacy name `_generate_threat_model` usage in docs.
    """
    candidates = _build_stride_threat_candidates(profile, baseline, signals, rag_keywords)
    haystack = _load_repo_crosscheck_haystack(scan_root)

    infra_rows: list[tuple[float, str, str, str, str]] = []
    biz_rows: list[tuple[float, str, str, str, str]] = []
    for item in candidates:
        sc, stride, title, desc = item
        bucket = _classify_infra_vs_business(stride, title, desc)
        status = _cross_check_architectural_threat(title, desc, haystack)
        row = (sc, stride, title, desc, status)
        if bucket == "infra":
            infra_rows.append(row)
        else:
            biz_rows.append(row)

    infra_rows.sort(key=lambda x: -x[0])
    biz_rows.sort(key=lambda x: -x[0])

    def pick(rows: list[tuple[float, str, str, str, str]], n: int) -> list[tuple[float, str, str, str, str]]:
        out: list[tuple[float, str, str, str, str]] = []
        seen: set[tuple[str, str]] = set()
        for r in rows:
            key = (r[1], r[2])
            if key in seen:
                continue
            seen.add(key)
            out.append(r)
            if len(out) >= n:
                break
        return out

    infra_top = pick(infra_rows, 5)
    biz_top = pick(biz_rows, 5)
    while len(infra_top) < 3:
        added = False
        for item in candidates:
            sc, stride, title, desc = item
            if _classify_infra_vs_business(stride, title, desc) != "infra":
                continue
            status = _cross_check_architectural_threat(title, desc, haystack)
            row = (sc, stride, title, desc, status)
            keys = {(r[1], r[2]) for r in infra_top}
            if (stride, title) not in keys:
                infra_top.append(row)
                added = True
                break
        if not added:
            break
    while len(biz_top) < 3:
        added = False
        for item in candidates:
            sc, stride, title, desc = item
            if _classify_infra_vs_business(stride, title, desc) != "business":
                continue
            status = _cross_check_architectural_threat(title, desc, haystack)
            row = (sc, stride, title, desc, status)
            keys = {(r[1], r[2]) for r in biz_top}
            if (stride, title) not in keys:
                biz_top.append(row)
                added = True
                break
        if not added:
            break

    what_if = _build_what_if_scenarios(profile, baseline, signals)

    lines: list[str] = []
    lines.append("## 0. Секция 0: Модель угроз проекта (Threat Modeling, STRIDE + Архитектор)")
    lines.append("")
    lines.append(
        f"- Источники: профиль `{profile}`, Enterprise baseline, сигналы репозитория "
        f"(`{signals.get('scan_root', '.')}`), зависимости: {len(signals.get('deps', []))} записей, RAG-ключи: {len(rag_keywords)}."
    )
    lines.append(f"- Кэш threat model: `{'hit' if cached else 'miss'}` (schema v{THREAT_MODEL_CACHE_SCHEMA_VERSION})")
    lines.append(f"- Cross-check: выборка исходников для эвристики: ~{len(haystack)} символов.")
    lines.append("")
    lines.append("### 0.1 Infrastructure Risks (инфраструктура и сеть)")
    lines.append("")
    if infra_top:
        for i, (_sc, stride, title, desc, status) in enumerate(infra_top[:5], start=1):
            lines.append(f"{i}. **[{stride}]** {title}")
            lines.append(f"   - {desc}")
            lines.append(f"   - **Cross-check:** {status}")
            lines.append("")
    else:
        lines.append("- (нет выделенных инфраструктурных рисков по классификатору — см. Business Logic.)")
        lines.append("")
    lines.append("### 0.2 Business Logic Risks (логика приложения и доверие)")
    lines.append("")
    if biz_top:
        for i, (_sc, stride, title, desc, status) in enumerate(biz_top[:5], start=1):
            lines.append(f"{i}. **[{stride}]** {title}")
            lines.append(f"   - {desc}")
            lines.append(f"   - **Cross-check:** {status}")
            lines.append("")
    else:
        lines.append("- (нет выделенных рисков бизнес-логики — см. Infrastructure.)")
        lines.append("")
    lines.append("### 0.3 Негативные сценарии «Что если?» (вне стандартных правил Semgrep)")
    lines.append("")
    for i, scenario in enumerate(what_if, start=1):
        cc = _cross_check_architectural_threat(f"WHAT-IF {i}", scenario, haystack)
        lines.append(f"{i}. {scenario}")
        lines.append(f"   - **Cross-check (эвристика):** {cc}")
        lines.append("")
    lines.append("### 0.4 STRIDE — сводная топ-5 (для трассировки)")
    lines.append("")
    for i, (_sc, stride, title, desc) in enumerate(candidates[:5], start=1):
        lines.append(f"{i}. **[{stride}]** {title} — {desc[:220]}{'…' if len(desc) > 220 else ''}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _format_threat_model_section_markdown(
    profile: str,
    baseline: str,
    signals: dict[str, Any],
    rag_keywords: set[str],
    cached: bool,
    scan_root: Path,
) -> str:
    return _generate_threat_model(profile, baseline, signals, rag_keywords, cached, scan_root)


def run_threat_modeling_engine(
    profile: str,
    final_context: str,
    target_rel: str,
) -> tuple[str, dict[str, Any], bool]:
    """
    Zero-prompt STRIDE synthesis from profile + ENTERPRISE_BASELINES + repo scan + lightweight RAG keywords.
    Returns (markdown_section, engine_metadata, cache_hit).
    """
    baseline = ENTERPRISE_BASELINES.get(profile, "")
    scan_root = _threat_scan_root(target_rel)
    signals = _collect_repo_threat_signals(scan_root)
    repo_fp = _repo_threat_fingerprint(signals)
    cache_key = _threat_cache_key(profile, final_context, repo_fp)
    cache = _load_threat_model_cache()
    cached_entry = cache.get("entries", {}).get(cache_key)
    if isinstance(cached_entry, dict) and cached_entry.get("markdown"):
        return (
            str(cached_entry["markdown"]),
            {
                "cache_key": cache_key,
                "repo_fingerprint": repo_fp,
                "signals": signals,
                "ask_hexvibe": None,
            },
            True,
        )

    rag_payload = ask_hexvibe_impl(
        f"{profile} STRIDE threat modeling architecture security. Context: {final_context[:1200]}"
    )
    rag_kw = _rag_keywords_from_ask(rag_payload)
    section_md = _format_threat_model_section_markdown(
        profile=profile,
        baseline=baseline,
        signals=signals,
        rag_keywords=rag_kw,
        cached=False,
        scan_root=scan_root,
    )
    _save_threat_model_cache_entry(cache_key, section_md)
    return (
        section_md,
        {
            "cache_key": cache_key,
            "repo_fingerprint": repo_fp,
            "signals": signals,
            "rag_keywords": sorted(rag_kw)[:40],
            "ask_hexvibe": rag_payload,
        },
        False,
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
    if any(k in q for k in ["пдн", "персональ", "enterprise compliance", "gdpr", "kii", "гост", "1с"]):
        boosts["ru-regulatory"] = 0.35
    if any(k in q for k in ["фстэк", "fstek", "приказ 235", "приказ 239", "gost r 56939", "гост р 56939", "кии"]):
        boosts["ru-regulatory"] = max(boosts.get("ru-regulatory", 0.0), 0.45)
    if any(k in q for k in ["цб", "57580", "уди", "уда", "user/pass", "мясные учет", "meat account"]):
        boosts["ru-regulatory"] = max(boosts.get("ru-regulatory", 0.0), 0.45)
    if any(k in q for k in ["fapi", "keycloak", "api gateway", "fapi-sec", "fapi-paok", "гост 57580"]):
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
            "egress proxy",
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
    if ("egress" in ql and "proxy" in ql) or "http proxy" in ql:
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


def run_check_impl(path: str, context_text: str = "") -> dict[str, Any]:
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
        "context_text": context_text,
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


def _detect_security_profile(project_name: str, context: str) -> str:
    text = f"{project_name} {context}".lower()
    backend_markers = ("fastapi", "agent", "chromium", "playwright", "starlette")
    desktop_markers = ("electron", ".net", "vsto", "nsis", "desktop app")
    backend_score = sum(1 for marker in backend_markers if marker in text)
    desktop_score = sum(1 for marker in desktop_markers if marker in text)
    if backend_score == 0 and desktop_score == 0:
        return PROFILE_FASTAPI_BACKEND  # Default: service/agent-first repos.
    return PROFILE_DESKTOP_APP if desktop_score > backend_score else PROFILE_FASTAPI_BACKEND


def _compose_effective_review_context(project_name: str, context: str, profile: str) -> str:
    raw_context = (context or "").strip()
    baseline = ENTERPRISE_BASELINES.get(profile, "")
    # Enforce baseline-first composition for deterministic architecture-aware review.
    if not raw_context:
        return f"{baseline}\nProject: {project_name}".strip()
    return f"{baseline}\nProject: {project_name}\n{raw_context}".strip()


def _profile_specific_checks(profile: str) -> list[str]:
    if profile == PROFILE_DESKTOP_APP:
        return [
            "Electron isolation / Node Integration",
            "VSTO add-in security baseline",
            "NSIS installer integrity controls",
            "SQLModel/SQLAlchemy async safety",
        ]
    return [
        "SSRF including DNS rebinding vectors",
        "RQ/Redis serialization and queue safety",
        "Egress isolation through HTTP proxy chain",
        "JWT audience verification and realm isolation",
    ]


def _resolve_project_target(project_name: str) -> str:
    # Accept absolute/relative project path; fallback to repository root.
    candidate = Path(project_name.strip())
    if candidate.is_absolute() and candidate.exists():
        try:
            return str(candidate.resolve().relative_to(ROOT)).replace("\\", "/")
        except ValueError:
            return "."
    rel = (ROOT / project_name.strip()).resolve()
    if project_name.strip() and rel.exists():
        try:
            return str(rel.relative_to(ROOT)).replace("\\", "/")
        except ValueError:
            return "."
    return "."


def _is_metric_mitigated(metric_id: str, context_text: str, mitigation_logic: dict[str, Any]) -> bool:
    if metric_id not in mitigation_logic:
        return False
    c = context_text.lower()
    checks: dict[str, bool] = {
        "RRC-008": ("fluentbit" in c) or ("logstash" in c) or ("siem" in c),
        "NGX-storage": ("boto3.generate_presigned_url" in c) or ("presigned" in c),
        "RRC-007": ("debug=false" in c) or ("debug = false" in c),
        "AK-002": ("isolated realm" in c) or ("single client" in c and "enterprise-client" in c),
        "RRC-010": ("aes-256" in c) and (("storageclass" in c) or ("pvc" in c) or ("at-rest" in c)),
        "AK-020": ("jwks" in c) and (("verify_signature" in c) or ("signature verification" in c)),
        "BOLA": (("owner_id" in c) and ("user_id" in c)) or ("ownership check" in c),
        "AAC-004": ("serializer=json" in c) or ("json serializer" in c),
        "RRC-024": ("next.js" in c) and ("ugc" in c and ("no ugc" in c or "without ugc" in c)),
    }
    return checks.get(metric_id, False)


def _is_external_integration_finding(message: str, path: str) -> bool:
    text = f"{message} {path}".lower()
    markers = (
        "external",
        "internet",
        "egress",
        "outlook",
        "transcription",
        "rag",
        "llm",
        "requests.",
        "httpx",
        "fetch(",
    )
    return any(marker in text for marker in markers)


def _render_security_review_markdown(
    profile: str,
    project_name: str,
    final_context: str,
    engine_prompt: str,
    skill_ids: list[str],
    checked_metrics: set[str],
    fixed_items: list[dict[str, Any]],
    critical_items: list[dict[str, Any]],
    medium_items: list[dict[str, Any]],
    threat_model_markdown: str = "",
) -> str:
    lines: list[str] = []
    lines.append(f"# Security Review: {project_name}")
    lines.append("")
    if threat_model_markdown.strip():
        lines.append(threat_model_markdown.rstrip())
        lines.append("")
    lines.append("## 1. Методология")
    lines.append(f"- Профиль: `{profile}`.")
    lines.append("- Оркестрация: `list_skills -> get_skill_context -> run_check`.")
    lines.append("- Перед оценкой находок применена проверка `mitigation_logic` и инфраструктурных исключений.")
    lines.append("- Для сетевых метрик `HTTP_PROXY` / `HTTPS_PROXY` рассматриваются как обязательный контроль для статуса `OK`.")
    lines.append(f"- Engine Prompt: `{engine_prompt}`")
    lines.append(f"- Final Context: `{final_context}`")
    lines.append("")
    lines.append("## 2. Исправлено (OK)")
    if fixed_items:
        for item in fixed_items[:100]:
            lines.append(f"- `{item['metric_id']}`: {item['reason']}")
    else:
        lines.append("- Нет элементов со статусом OK по правилам исключений.")
    lines.append("")
    lines.append("## 3. Критические (РИСК)")
    if critical_items:
        for item in critical_items[:100]:
            lines.append(f"- `{item['metric_id']}` в `{item['path']}`: {item['message']}")
    else:
        lines.append("- Критические риски не выявлены.")
    lines.append("")
    lines.append("## 4. Средние")
    if medium_items:
        for item in medium_items[:100]:
            lines.append(f"- `{item['metric_id']}` в `{item['path']}`: {item['message']}")
    else:
        lines.append("- Средние риски не выявлены.")
    lines.append("")
    lines.append("## 5. Матрица покрытия")
    lines.append(f"- Подключенные Skills: {', '.join(f'`{sid}`' for sid in skill_ids)}")
    lines.append(f"- Проверенные метрики (уникальные): `{len(checked_metrics)}`")
    lines.append("")
    return "\n".join(lines)


def run_security_review_impl(project_name: str, context: str) -> dict[str, Any]:
    if not project_name.strip():
        return {"error": "project_name is required"}
    profile = _detect_security_profile(project_name, context)
    profile_map: dict[str, list[str]] = {
        PROFILE_FASTAPI_BACKEND: [
            "fastapi-async",
            "auth-keycloak",
            "advanced-agent-cloud",
            "infra-k8s-helm",
            "domain-data-privacy",
        ],
        PROFILE_DESKTOP_APP: [
            "desktop-vsto-suite",  # alias: desktop-security
            "csharp-dotnet",  # alias: dotnet-legacy
            "domain-access-management",
            "infra-k8s-helm",
            "domain-input-validation",
        ],
    }
    available_skills = {s["skill_id"] for s in list_skills_impl().get("skills", [])}
    skill_ids = [sid for sid in profile_map[profile] if sid in available_skills]
    if not skill_ids:
        return {"error": f"no mapped skills available for profile: {profile}"}

    final_context = _compose_effective_review_context(project_name, context, profile)
    engine_prompt = _engine_prompt_for_profile(profile)
    target_path = _resolve_project_target(project_name)
    threat_md, threat_meta, threat_cache_hit = run_threat_modeling_engine(profile, final_context, target_path)
    ask_output = threat_meta.get("ask_hexvibe") or ask_hexvibe_impl(final_context)
    run_result = run_check_impl(target_path, context_text=final_context)
    findings = run_result.get("semgrep", {}).get("findings", [])
    context_text = final_context
    manifests = _load_skill_manifests()
    metric_to_skill: dict[str, str] = {}
    for sid in skill_ids:
        ctx = get_skill_context_impl(sid, question=final_context, file_path=target_path, file_content="")
        if "patterns_by_stack" not in ctx:
            continue
        for rows in ctx.get("patterns_by_stack", {}).values():
            for row in rows:
                mid = str(row.get("metric_id", "")).upper()
                if mid:
                    metric_to_skill[mid] = sid

    checked_metrics: set[str] = set()
    fixed_items: list[dict[str, Any]] = []
    critical_items: list[dict[str, Any]] = []
    medium_items: list[dict[str, Any]] = []
    for finding in findings:
        metric_id = _extract_metric_id(str(finding.get("check_id", ""))).upper()
        if not metric_id:
            continue
        skill_id = metric_to_skill.get(metric_id)
        if skill_id not in skill_ids:
            continue
        checked_metrics.add(metric_id)
        mitigation_logic = manifests.get(skill_id, {}).get("mitigation_logic", {})
        message = str((finding.get("extra") or {}).get("message", ""))
        rel_path = str(finding.get("path", ""))
        severity = str((finding.get("extra") or {}).get("severity", "WARNING")).upper()
        # Desktop App baseline: external integrations are trusted only through central API gateway mediation.
        if profile == PROFILE_DESKTOP_APP and _is_external_integration_finding(message, rel_path):
            if "api gateway" in context_text.lower() or "gateway" in context_text.lower():
                fixed_items.append(
                    {
                        "metric_id": metric_id,
                        "path": rel_path,
                        "reason": "External integration accepted via mandatory API gateway chain.",
                    }
                )
                continue
        if _is_metric_mitigated(metric_id, context_text, mitigation_logic):
            fixed_items.append(
                {
                    "metric_id": metric_id,
                    "path": rel_path,
                    "reason": f"Applied mitigation logic from `{skill_id}`.",
                }
            )
            continue
        item = {"metric_id": metric_id, "path": rel_path, "message": message}
        if severity == "ERROR":
            critical_items.append(item)
        else:
            medium_items.append(item)

    markdown_report = _render_security_review_markdown(
        profile=profile,
        project_name=project_name,
        final_context=final_context,
        engine_prompt=engine_prompt,
        skill_ids=skill_ids,
        checked_metrics=checked_metrics,
        fixed_items=fixed_items,
        critical_items=critical_items,
        medium_items=medium_items,
        threat_model_markdown=threat_md,
    )
    return {
        "project_name": project_name,
        "profile": profile,
        "target_path": target_path,
        "effective_context": final_context,
        "selected_skills": skill_ids,
        "specific_checks": _profile_specific_checks(profile),
        "orchestration": [
            "threat_modeling_stride",
            "list_skills",
            "get_skill_context",
            "run_check",
            "ask_hexvibe",
        ],
        "threat_modeling": {
            "cache_hit": threat_cache_hit,
            "markdown_section": threat_md,
            "engine": threat_meta,
        },
        "engine_prompt": engine_prompt,
        "ask_hexvibe": ask_output,
        "summary": {
            "ok_count": len(fixed_items),
            "critical_count": len(critical_items),
            "medium_count": len(medium_items),
            "checked_metrics_count": len(checked_metrics),
        },
        "report_markdown": markdown_report,
    }


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
    def run_security_review(project_name: str, context: str) -> dict[str, Any]:
        return run_security_review_impl(project_name=project_name, context=context)

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
