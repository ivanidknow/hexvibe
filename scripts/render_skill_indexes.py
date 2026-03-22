"""
One-off helper: regenerate skills/*/index.md bodies with TOC from patterns.md.
Run from repo root: python scripts/render_skill_indexes.py
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DETECTION_SUMMARY = ROOT / "core" / "gold-standard-testbed" / "detection-summary.json"
SKILLS = ROOT / "core" / "skills"

ID_RE = re.compile(r"^[A-Z0-9]{2,4}-[0-9A-Za-z.\-]+$")


def parse_toc(md: Path) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    for raw in md.read_text(encoding="utf-8").splitlines():
        line = re.sub(r"\s*<!--.*?-->\s*$", "", raw).strip()
        if not (line.startswith("|") and line.endswith("|")):
            continue
        parts = [p.strip() for p in line.split("|")[1:-1]]
        if len(parts) < 5:
            continue
        tid = parts[0]
        if not ID_RE.match(tid):
            continue
        title = parts[1]
        # New format: ... | Stack | Source |
        # Fallback for legacy: ... | Source |
        stack = parts[-2] if len(parts) >= 6 else "Generic"
        title = re.sub(r"<br\s*/?>", " ", title, flags=re.I)
        title = re.sub(r"\s+", " ", title)
        if len(title) > 90:
            title = title[:87] + "..."
        out.append((tid, title, stack))
    return out


def md_table(rows: list[tuple[str, str, str]]) -> str:
    has_stack = any(bool(stack.strip()) for _, _, stack in rows)
    if has_stack:
        lines = ["| ID | Metric | Stack |", "|---|---|---|"]
    else:
        lines = ["| ID | Metric |", "|---|---|"]
    for tid, title, stack in rows:
        title = title.replace("|", "\\|")
        if has_stack:
            lines.append(f"| `{tid}` | {title} | {stack or 'Generic'} |")
        else:
            lines.append(f"| `{tid}` | {title} |")
    return "\n".join(lines)


def threats_by_stack(rows: list[tuple[str, str, str]]) -> list[str]:
    grouped: dict[str, list[tuple[str, str]]] = {}
    for tid, title, stack in rows:
        s = (stack or "Generic").strip()
        grouped.setdefault(s, []).append((tid, title))
    out: list[str] = []
    for stack, items in sorted(grouped.items(), key=lambda kv: (-len(kv[1]), kv[0].lower())):
        sample = ", ".join(f"`{tid}`" for tid, _ in items[:4])
        out.append(f"**{stack}**: {len(items)} metrics ({sample})")
    return out


def _compliance_standards_table() -> str:
    if not DETECTION_SUMMARY.exists():
        return ""
    try:
        data = json.loads(DETECTION_SUMMARY.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return ""
    comp = data.get("compliance") or {}
    if not isinstance(comp, dict):
        return ""
    ow = comp.get("owasp_top10_2021") or {}
    at = comp.get("mitre_attack_enterprise") or {}
    nist = comp.get("nist_ssdf_po") or {}
    lines = [
        "## Standards coverage (Paladin compliance layer)",
        "",
        "Aggregated from `CWE-*` tokens in `patterns.md` via `scripts/compliance_layer.py` "
        "(OWASP Top 10 **2021** categories; representative MITRE ATT&CK **Enterprise** techniques; "
        "NIST SSDF PO fields are proxy counts).",
        "",
        "| Standard | Category | Patterns (rules tagged) | Status |",
        "|---|---|---:|---|",
    ]
    total = int(data.get("total_ids") or 0)
    tagged = int(comp.get("rules_with_compliance_tags") or 0)
    for k in sorted(ow.keys()):
        lines.append(f"| OWASP Top 10 (2021) | {k} | {ow[k]} | Covered |")
    for k in sorted(at.keys()):
        lines.append(f"| MITRE ATT&CK (Enterprise) | {k} | {at[k]} | Mapped |")
    if isinstance(nist, dict):
        for k in sorted(nist.keys()):
            lines.append(f"| NIST SSDF (proxy) | {k} | {nist[k]} | Indicative |")
    lines.append(
        f"| **HexVibe rules** | Total IDs in matrix | {total} | "
        f"{'OK' if total and tagged else 'Regenerate'} |"
    )
    lines.append(
        f"| **Compliance tags** | Rules with OWASP+MITRE tags | {tagged} | "
        f"See `rule-compliance-map.json` |"
    )
    lines.append("")
    return "\n".join(lines)


def write_global_skills_index() -> None:
    entries: list[tuple[str, str, int, str, str]] = []
    unique_ids: set[str] = set()
    default_stack_by_skill = {
        "advanced-agent-cloud": "Agent/Browser",
        "app-logic": "Application Logic",
        "auth-keycloak": "Identity/OIDC",
        "browser-agent": "Browser Automation",
        "cloud-secrets": "Cloud/Secrets",
        "csharp-dotnet": ".NET/C#",
        "desktop-vsto-suite": "Electron/Desktop/.NET",
        "devops-security": "DevOps/Supply Chain",
        "fastapi-async": "Python/FastAPI",
        "go-core": "Go",
        "infra-k8s-helm": "Kubernetes/Infra",
        "integration-security": "Integration/API",
        "java-spring": "Java/Spring",
        "license-compliance": "Compliance/License",
        "nodejs-nestjs": "Node.js/NestJS",
        "observability": "Observability",
        "ru-regulatory": "Compliance/Regulatory",
        "ruby-rails": "Ruby/Rails",
    }
    for d in sorted(SKILLS.iterdir()):
        if not d.is_dir():
            continue
        p = d / "patterns.md"
        if not p.exists():
            continue
        rows = parse_toc(p)
        if not rows:
            continue
        counts: dict[str, int] = {}
        if d.name.startswith("domain-"):
            for rid, _, stack in rows:
                unique_ids.add(rid)
                s = (stack or "Generic").strip()
                counts[s] = counts.get(s, 0) + 1
        else:
            for rid, _, _ in rows:
                unique_ids.add(rid)
            defaults = default_stack_by_skill.get(d.name, "Generic")
            counts[defaults] = len(rows)
        top_stack = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0].lower()))[0][0]
        stack_summary = ", ".join(
            f"{s}:{n}" for s, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0].lower()))[:3]
        )
        entries.append((d.name, str(p.parent.relative_to(ROOT)).replace("\\", "/"), len(rows), top_stack, stack_summary))

    lines = [
        "# HexVibe Skills Index",
        "",
        "Central catalog of all security domains under `core/skills/`.",
        "",
        "| Domain | Path | Rules | Primary Stack | Stack Summary |",
        "|---|---|---:|---|---|",
    ]
    total = 0
    for name, rel_path, count, primary, summary in entries:
        total += count
        domain_title = name.replace("-", " ").title()
        lines.append(f"| {domain_title} | `{rel_path}/` | {count} | {primary} | {summary} |")
    lines.extend(["", f"**Total unique rules:** {len(unique_ids)}", f"**Total rows across domains:** {total}", ""])
    comp_tbl = _compliance_standards_table()
    if comp_tbl:
        lines.append(comp_tbl)
    (SKILLS / "index.md").write_text("\n".join(lines), encoding="utf-8")


# Domain-specific metadata: overview, threats, verification paths, optional notes
META: dict[str, dict] = {
    "advanced-agent-cloud": {
        "title": "Advanced Agent & Cloud",
        "stack": (
            "Covers automation agents that combine **headless browsers** (Playwright), **JavaScript/Node** surfaces "
            "(Next.js public env), **Python** workers and queues (RQ/redis), **object storage** (S3/MinIO-style), "
            "**reverse proxies** (Nginx), **egress controls**, and **real-time** browser APIs (WebRTC). "
            "Metrics are prefixed **`AAC`**."
        ),
        "threats": [
            "**SSRF and navigation abuse** via browser automation (`AAC-001`, `AAC-008`).",
            "**Secret and PII leakage** through client bundles, traces, or logs (`AAC-002`, `AAC-003`, `AAC-009`).",
            "**Unsafe deserialization and queue trust** (`AAC-004`) and **weak object-store policy** (`AAC-005`).",
            "**Broken identity validation** against OIDC/Keycloak expectations (`AAC-006`).",
            "**Missing rate limits / DoS** at the edge (`AAC-007`) and **ambient capture** (`AAC-010`).",
        ],
        "verify": [
            "[`gold-standard-testbed/aac_vulnerable.py`](../gold-standard-testbed/aac_vulnerable.py)",
            "[`gold-standard-testbed/aac_vulnerable.ts`](../gold-standard-testbed/aac_vulnerable.ts)",
        ],
        "extra": (
            "**Product alignment:** critical for **Dion Agent** — browser-bound automation, queues, and cloud-adjacent "
            "controls must stay aligned with these metrics."
        ),
    },
    "desktop-vsto-suite": {
        "title": "Desktop & Office Integration Suite",
        "stack": (
            "**Electron** desktop shells (renderer hardening, IPC), **.NET / VSTO** Office add-ins (legacy deserialization, "
            "XML, secrets in config), **NSIS** installers, and **document / AI client** pipelines: **xlsx** (SheetJS), "
            "**docx**/PizZip, **mammoth**, **pdfjs-dist**, **word-extractor**, **OpenAI SDK** responses, and **main-process** "
            "hardening (`nodeIntegration: false`, `contextIsolation: true`, `senderFrame` checks). Metrics are prefixed **`INS`**."
        ),
        "threats": [
            "**Renderer compromise** via disabled isolation or Node in the page (`INS-001`, `INS-002`).",
            "**Remote code execution** through IPC bridges (`INS-003`).",
            "**Deserialization and XXE** in legacy .NET stacks (`INS-004`, `INS-005`).",
            "**Document chain:** XXE/zip-bomb/Excel formula injection (`INS-072`…`INS-091`, CWE-611/409/1236).",
            "**OpenAI integration:** unvalidated structured output and prompt logging (`INS-092`…`INS-099`, CWE-1027/1109/201).",
            "**Electron runtime:** explicit webPreferences, IPC sender validation (`INS-100`…`INS-110`).",
            "**Installer DLL hijacking** (`INS-006`) and **cleartext credentials** (`INS-007`).",
        ],
        "verify": [
            "[`gold-standard-testbed/insight_vulnerable.ts`](../gold-standard-testbed/insight_vulnerable.ts)",
            "[`gold-standard-testbed/insight_vulnerable.cs`](../gold-standard-testbed/insight_vulnerable.cs)",
        ],
        "extra": "",
    },
    "desktop-electron-pro": {
        "title": "Desktop Electron Pro",
        "stack": (
            "Security controls for **Electron desktop** runtime channels and dependency posture, based on "
            "real assessment findings from Insight. Metrics are prefixed **`DSK`**."
        ),
        "threats": [
            "Renderer-to-main unsafe code execution paths (`DSK-100`).",
            "Sensitive operation exposure through weak IPC contracts (`DSK-105`).",
            "Prototype pollution supply-chain risk through outdated parser libs (`DSK-110`).",
        ],
        "verify": ["[`gold-standard-testbed/gap_fill_vulnerable.py`](../gold-standard-testbed/gap_fill_vulnerable.py)"],
    },
    "domain-access-management": {
        "title": "Domain Access Management",
        "stack": "Authentication, authorization, BOLA/IDOR, session controls, and architectural auth risks grouped by function.",
        "threats": [
            "Fail-open auth and weak claim validation.",
            "Missing ownership/tenant checks for protected objects.",
            "Session/token lifecycle gaps and replay surfaces.",
        ],
        "verify": ["[`gold-standard-testbed/gap_fill_vulnerable.py`](../gold-standard-testbed/gap_fill_vulnerable.py)"],
    },
    "domain-data-privacy": {
        "title": "Domain Data Privacy",
        "stack": "PII and secret leakage controls across logs, traces, browser storage, and runtime diagnostics.",
        "threats": [
            "Sensitive data leakage in logs/console/errors.",
            "Weak client-side data handling and source map exposure.",
            "Privacy non-compliance for regulated data.",
        ],
        "verify": ["[`gold-standard-testbed/gap_fill_vulnerable.py`](../gold-standard-testbed/gap_fill_vulnerable.py)"],
    },
    "domain-platform-hardening": {
        "title": "Domain Platform Hardening",
        "stack": "Hardening for mobile/desktop/runtime/infrastructure platform controls and operational guardrails.",
        "threats": [
            "Insecure platform defaults and runtime policy gaps.",
            "Dependency and transport hardening weaknesses.",
            "Missing resource and resilience constraints.",
        ],
        "verify": ["[`gold-standard-testbed/gap_fill_vulnerable.py`](../gold-standard-testbed/gap_fill_vulnerable.py)"],
    },
    "domain-input-validation": {
        "title": "Domain Input Validation",
        "stack": "Canonical validation controls for untrusted input: traversal, SSRF, code/command injection, and unsafe parsing.",
        "threats": [
            "Unsanitized/unnormalized path and URL input.",
            "Injection via SQL, shell, eval-like execution.",
            "Unverified signatures and malformed payload handling.",
        ],
        "verify": ["[`gold-standard-testbed/gap_fill_vulnerable.py`](../gold-standard-testbed/gap_fill_vulnerable.py)"],
    },
    "mobile-flutter": {
        "title": "Mobile Flutter",
        "stack": (
            "Mobile app hardening for **Flutter** and Android host integration from Silk Mobile assessment patterns. "
            "Metrics are prefixed **`MOB`**."
        ),
        "threats": [
            "TLS trust bypass via permissive certificate callbacks (`MOB-001`).",
            "Token disclosure through debug logging paths (`MOB-010`).",
            "Screen privacy leakage without `FLAG_SECURE` protection (`MOB-021`).",
        ],
        "verify": ["[`gold-standard-testbed/gap_fill_vulnerable.py`](../gold-standard-testbed/gap_fill_vulnerable.py)"],
    },
    "fastapi-async": {
        "title": "FastAPI / Async SQLAlchemy",
        "stack": (
            "Async **FastAPI** APIs with **Encode Databases** / SQLAlchemy patterns, **SlowAPI**, **Pydantic**, "
            "and Python security baselines. Metrics are prefixed **`FAS`**."
        ),
        "threats": [
            "Injection and unsafe query construction (`FAS-004`, `FAS-005`, `FAS-021`, `FAS-024`–`FAS-027`).",
            "Broken async/resource hygiene (`FAS-006`–`FAS-009`, `FAS-020`).",
            "Information disclosure and misconfiguration (`FAS-010`–`FAS-013`, `FAS-019`).",
            "AuthZ and object-level flaws (`FAS-016`, `FAS-017`, `FAS-018`).",
        ],
        "verify": ["[`gold-standard-testbed/api_vulnerable.py`](../gold-standard-testbed/api_vulnerable.py)"],
        "integration_module": "verify_fastapi_async_poc.py",
    },
    "auth-keycloak": {
        "title": "Auth / Keycloak / OIDC",
        "stack": (
            "**OAuth2/OIDC** clients, **JWT** validation, **Keycloak** integration, token exchange, and "
            "browser-flow hardening. Metrics are prefixed **`AK`**."
        ),
        "threats": [
            "Algorithm confusion and weak JWT validation (`AK-001`, `AK-002`, `AK-008`, `AK-016`).",
            "Redirect and session fixation (`AK-004`, `AK-006`, `AK-015`, `AK-016`).",
            "Secret handling and token forwarding (`AK-005`, `AK-007`, `AK-011`–`AK-014`).",
            "PKCE, DPoP, and operational abuse (`AK-009`, `AK-010`, `AK-012`).",
        ],
        "verify": ["[`gold-standard-testbed/api_vulnerable.py`](../gold-standard-testbed/api_vulnerable.py)"],
        "integration_module": "verify_auth_keycloak_poc.py",
    },
    "infra-k8s-helm": {
        "title": "Infra / Kubernetes / Helm / Docker",
        "stack": (
            "**Kubernetes** manifests, **Helm** values, **Docker** images, and **NGINX** hardening. "
            "Metrics use the **`INF-*`** namespace (including dotted IDs)."
        ),
        "threats": [
            "Privileged containers, weak TLS, and bad defaults in images (`INF-4.*`, `INF-5.*`, `INF-010`–`INF-014`).",
            "NGINX and ingress misconfiguration (`INF-5.3.*`, `INF-5.5.*`, `INF-5.6.*`).",
        ],
        "verify": [
            "[`gold-standard-testbed/infra_vulnerable.yaml`](../gold-standard-testbed/infra_vulnerable.yaml)",
            "[`gold-standard-testbed/Dockerfile`](../gold-standard-testbed/Dockerfile)",
            "[`gold-standard-testbed/nginx.conf`](../gold-standard-testbed/nginx.conf)",
        ],
        "integration_module": "verify_infra_k8s_helm_poc.py",
    },
    "browser-agent": {
        "title": "Browser Agent (Playwright / automation)",
        "stack": (
            "**Playwright**-driven automation in Python and JavaScript: sandbox, navigation, downloads, "
            "and script execution boundaries. Metrics are prefixed **`BRW`**."
        ),
        "threats": [
            "Unsafe Chromium flags and TLS downgrades (`BRW-001`–`BRW-003`, `BRW-006`).",
            "SSRF and local metadata access via `goto` (`BRW-007`, `BRW-008`).",
            "XSS / JS injection / prototype pollution in bridged code (`BRW-011`–`BRW-013`).",
        ],
        "verify": ["[`gold-standard-testbed/browser_vulnerable.js`](../gold-standard-testbed/browser_vulnerable.js)"],
    },
    "app-logic": {
        "title": "Application Business Logic",
        "stack": (
            "Cross-cutting **BOLA/BOPLA**, workflow, webhook, and abuse-resistant business rules on typical "
            "FastAPI-style services. Metrics are prefixed **`BIZ`**."
        ),
        "threats": [
            "Object and property-level authorization gaps (`BIZ-001`–`BIZ-004`, `BIZ-009`).",
            "Step-up auth and replay/idempotency (`BIZ-005`–`BIZ-008`, `BIZ-010`).",
            "SSRF and trust of internal services (`BIZ-011`, `BIZ-012`).",
            "Shadow APIs, exports, and webhooks (`BIZ-013`, `BIZ-016`–`BIZ-019`).",
        ],
        "verify": ["[`gold-standard-testbed/api_vulnerable.py`](../gold-standard-testbed/api_vulnerable.py)"],
        "integration_module": "verify_app_logic_poc.py",
    },
    "observability": {
        "title": "Observability & Audit Logging",
        "stack": (
            "Structured logging, trace correlation, audit integrity, and security telemetry for Python services. "
            "Metrics are prefixed **`LOG`**."
        ),
        "threats": [
            "Silent failures and missing correlation (`LOG-001`–`LOG-003`, `LOG-010`).",
            "PII/secrets in logs and verbose errors (`LOG-004`, `LOG-005`, `LOG-012`).",
            "Missing audit for admin and auth events (`LOG-006`, `LOG-007`, `LOG-014`).",
            "Log injection (`LOG-011`).",
        ],
        "verify": ["[`gold-standard-testbed/api_vulnerable.py`](../gold-standard-testbed/api_vulnerable.py)"],
        "integration_module": "verify_observability_poc.py",
    },
    "java-spring": {
        "title": "Java / Spring",
        "stack": (
            "Server-side **Java** with **Spring**-style patterns: injection, deserialization, JWT, multipart, "
            "and path handling. Metrics are prefixed **`JAVA`**."
        ),
        "threats": [
            "Code/exec and SpEL/Jackson risks (`JAVA-001`–`JAVA-011`).",
            "XXE and Spring Security misconfig (`JAVA-012`–`JAVA-014`).",
            "Open redirect, JWT checks, crypto (`JAVA-015`–`JAVA-020`).",
        ],
        "verify": [
            "[`gold-standard-testbed/multi_lang_vulnerable/java_vulnerable.java`](../gold-standard-testbed/multi_lang_vulnerable/java_vulnerable.java)"
        ],
    },
    "csharp-dotnet": {
        "title": "C# / .NET",
        "stack": (
            "**ASP.NET** / .NET patterns: Roslyn, process execution, XML, cookies, crypto, and redirects. "
            "Metrics are prefixed **`CSH`**."
        ),
        "threats": [
            "Code/command injection and unsafe reflection (`CSH-001`–`CSH-008`).",
            "Deserialization and XXE (`CSH-009`, `CSH-010`).",
            "Secrets, cookies, TLS (`CSH-011`–`CSH-015`, `CSH-016`).",
        ],
        "verify": [
            "[`gold-standard-testbed/multi_lang_vulnerable/csharp_vulnerable.cs`](../gold-standard-testbed/multi_lang_vulnerable/csharp_vulnerable.cs)"
        ],
    },
    "go-core": {
        "title": "Go Core",
        "stack": (
            "**Go** services: `net/http`, SQL/ORM, gRPC, `unsafe`/CGO edges, and concurrency. "
            "Metrics are prefixed **`GO`**."
        ),
        "threats": [
            "Command injection and unsafe `exec` (`GO-001`–`GO-008`, `GO-021`).",
            "SSRF, path traversal, open redirect (`GO-010`, `GO-011`, `GO-014`, `GO-026`).",
            "Weak crypto and JWT mistakes (`GO-013`, `GO-016`, `GO-018`, `GO-031`, `GO-040`).",
            "Concurrency and resource limits (`GO-009`, `GO-019`, `GO-023`, `GO-030`, `GO-032`).",
        ],
        "verify": [
            "[`gold-standard-testbed/multi_lang_vulnerable/go_vulnerable.go`](../gold-standard-testbed/multi_lang_vulnerable/go_vulnerable.go)"
        ],
    },
    "ruby-rails": {
        "title": "Ruby / Rails",
        "stack": (
            "**Rails**-style controllers and Ruby idioms: `eval`, YAML, mass assignment, redirects, and SSRF. "
            "Metrics are prefixed **`RUBY`**."
        ),
        "threats": [
            "Code/command injection and ERB (`RUBY-001`–`RUBY-003`, `RUBY-006`, `RUBY-012`).",
            "Unsafe YAML and mass assignment (`RUBY-008`–`RUBY-011`).",
            "Open redirect, cookies, SSRF (`RUBY-013`–`RUBY-014`, `RUBY-017`).",
        ],
        "verify": [
            "[`gold-standard-testbed/multi_lang_vulnerable/ruby_vulnerable.rb`](../gold-standard-testbed/multi_lang_vulnerable/ruby_vulnerable.rb)"
        ],
    },
    "python-django": {
        "title": "Python / Django",
        "stack": (
            "**Django** views, ORM, templates, settings, and session security. Metrics are prefixed **`DJA`**."
        ),
        "threats": [
            "CSRF, SQLi, debug/config exposure (`DJA-001`–`DJA-003`, `DJA-005`).",
            "Mass assignment, redirects, cookies (`DJA-004`, `DJA-006`–`DJA-009`).",
            "XSS, sessions, weak hashing (`DJA-011`–`DJA-014`).",
        ],
        "verify": ["[`gold-standard-testbed/django_vulnerable.py`](../gold-standard-testbed/django_vulnerable.py)"],
    },
    "python-backend-pro": {
        "title": "Python Backend Pro",
        "stack": (
            "Backend API controls extracted from Silk Backend security assessments for auth hardening, object-level "
            "authorization, and filesystem safety. Metrics are prefixed **`PY-1xx`**."
        ),
        "threats": [
            "Fail-open authentication behavior on missing env secrets (`PY-100`).",
            "Object-level access control failures in Django querysets (`PY-105`).",
            "Path traversal on media/file operations (`PY-110`).",
        ],
        "verify": ["[`gold-standard-testbed/gap_fill_vulnerable.py`](../gold-standard-testbed/gap_fill_vulnerable.py)"],
    },
    "nodejs-nestjs": {
        "title": "Node.js / NestJS",
        "stack": (
            "**NestJS** / Express patterns: validation pipes, ORM raw queries, CORS, JWT, throttling, and logging. "
            "Metrics are prefixed **`NST`**."
        ),
        "threats": [
            "Prototype pollution and CORS (`NST-001`, `NST-002`).",
            "SQL/Prisma injection and SSRF (`NST-004`, `NST-005`, `NST-014`).",
            "AuthZ and guard mistakes (`NST-006`, `NST-008`, `NST-015`, `NST-016`).",
        ],
        "verify": ["[`gold-standard-testbed/nestjs_vulnerable.ts`](../gold-standard-testbed/nestjs_vulnerable.ts)"],
    },
    "license-compliance": {
        "title": "License Compliance",
        "stack": (
            "Dependency manifest policy for copyleft licenses (AGPL/SSPL), trusted package sources, and "
            "SBOM/lockfile evidence for `package.json` / `requirements.txt`. "
            "Metrics are prefixed **`LIC`**."
        ),
        "threats": [
            "Direct and transitive copyleft exposure (`LIC-001`, `LIC-002`, `LIC-009`).",
            "Unknown metadata and untrusted sources in dependency pipeline (`LIC-004`, `LIC-005`).",
            "Missing CI/SBOM evidence for license governance (`LIC-006`, `LIC-008`).",
            "Binary artifact license/provenance gaps (`LIC-010`).",
        ],
        "verify": ["[`gold-standard-testbed/license_compliance_vulnerable.py`](../gold-standard-testbed/license_compliance_vulnerable.py)"],
        "extra": (
            "**Verification note:** LIC checks may require running **Syft via Docker/MCP** to produce SBOM "
            "(CycloneDX/SPDX) and detect transitive license risk not visible in manifests."
        ),
    },
    "ru-regulatory": {
        "title": "RU Regulatory (152-FZ / КИИ)",
        "stack": (
            "Russian regulatory controls for PII logging (152-FZ), data residency/anonymization before foreign AI APIs, "
            "GOST / certified crypto usage inside KII, and import substitution portability. Metrics are prefixed **`RRC`**."
        ),
        "threats": [
            "Logging PII to stdout or external log systems (`RRC-001`).",
            "Sending PII to foreign APIs (OpenAI/Claude) without anonymization (`RRC-002`).",
            "Non-certified / unsafe crypto libraries in the KII contour (`RRC-003`).",
            "Hardcoded cloud metadata (e.g. AWS IMDS) hurting migration/import substitution (`RRC-004`).",
        ],
        "verify": ["[`gold-standard-testbed/ru_regulatory_vulnerable.py`](../gold-standard-testbed/ru_regulatory_vulnerable.py)"],
    },
    "cloud-secrets": {
        "title": "Cloud & Secrets",
        "stack": (
            "Cloud-native secret management and workload hardening across **Kubernetes YAML** and **Python services**: "
            "metadata SSRF, IAM/KMS/Vault hygiene, ENV/log leakage, and JWT trust boundaries. Metrics are prefixed **`SEC`**."
        ),
        "threats": [
            "Metadata SSRF and exposed cloud identity surfaces (`SEC-001`, `SEC-007`).",
            "Kubernetes workload misconfigurations around secrets and privilege (`SEC-002`–`SEC-005`).",
            "Secret leakage to logs, endpoints, and CI output (`SEC-006`, `SEC-013`, `SEC-015`).",
            "JWT/Vault/KMS misuse and missing secret lifecycle controls (`SEC-008`–`SEC-012`, `SEC-014`).",
        ],
        "verify": [
            "[`gold-standard-testbed/cloud_secrets_vulnerable.py`](../gold-standard-testbed/cloud_secrets_vulnerable.py)",
            "[`gold-standard-testbed/cloud_secrets_vulnerable.yaml`](../gold-standard-testbed/cloud_secrets_vulnerable.yaml)",
        ],
        "extra": (
            "**Product alignment:** cloud workload hardening, metadata egress controls, and secret governance "
            "must map to SEC metrics before release."
        ),
    },
}


def verification_section(skill: str, paths: list[str], integration_module: str | None) -> str:
    lines = [
        "## Verification",
        "",
        "**Verification:** Check the gold testbed file(s) below for `Vulnerable: <ID>` markers "
        "(static Semgrep + `detection-matrix.md` ground truth).",
        "",
    ]
    for p in paths:
        lines.append(f"- {p}")
    if integration_module:
        lines.extend(
            [
                "",
                "**Optional HTTP integration tests** (pytest + httpx; require a running API, "
                "`HEXVIBE_TARGET_URL`): "
                f"[`gold-standard-testbed/integration/{integration_module}`](../gold-standard-testbed/integration/{integration_module}). "
                "See [`gold-standard-testbed/integration/README.md`](../gold-standard-testbed/integration/README.md).",
            ]
        )
    lines.extend(
        [
            "",
            "After changing [`patterns.md`](patterns.md), run from the repo root:",
            "",
            "```bash",
            "python scripts/sync_semgrep.py",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def workflow_section() -> str:
    return "\n".join(
        [
            "## Workflow: Recon → Scan → Verify",
            "",
            "### 1) Recon",
            "- Map entrypoints, data flows, and trust boundaries for this stack.",
            "- Identify which metrics in [`patterns.md`](patterns.md) apply to the code under review.",
            "",
            "### 2) Scan",
            "- Run Semgrep with `semgrep-rules/<skill>.yaml` (generated) and correlate with Anti-Patterns.",
            "- Eliminate findings that cannot bind to a metric row.",
            "",
            "### 3) Verify",
            "- Confirm markers or scanner hits for touched IDs in the gold testbed when adding metrics.",
            "- Emit findings as `Vulnerable: <PREFIX>-<NNN>` in written reviews.",
            "",
        ]
    )


def render_index(skill_dir: Path) -> str:
    skill = skill_dir.name
    patterns = skill_dir / "patterns.md"
    if not patterns.exists():
        raise FileNotFoundError(patterns)
    meta = META.get(
        skill,
        {
            "title": skill.replace("-", " ").title(),
            "stack": f"See [`patterns.md`](patterns.md) for Anti-Pattern / Safe-Pattern definitions for this domain.",
            "threats": ["Map concrete rows from the pattern table to your architecture."],
            "verify": ["[`gold-standard-testbed/`](../gold-standard-testbed/) (see `detection-matrix.md` for ID → file mapping)"],
        },
    )
    toc_rows = parse_toc(patterns)
    integration_module = meta.get("integration_module")

    parts = [
        f"# {meta['title']}",
        "",
        "## Stack overview",
        "",
        meta["stack"],
        "",
    ]
    if meta.get("extra"):
        parts.extend([meta["extra"], ""])
    parts.extend(
        [
            "## Top threats",
            "",
        ]
    )
    if skill.startswith("domain-"):
        threat_lines = threats_by_stack(toc_rows)
    else:
        threat_lines = list(meta["threats"])
    for t in threat_lines:
        parts.append(f"- {t}")
    parts.extend(
        [
            "",
            "## Pattern catalog",
            "",
            "Complete Anti-Pattern / Safe-Pattern definitions live in [`patterns.md`](patterns.md). "
            "The table below is a **table of contents** by metric ID.",
            "",
            md_table(toc_rows),
            "",
        ]
    )
    parts.append(verification_section(skill, meta["verify"], integration_module))
    parts.append(workflow_section())
    return "\n".join(parts) + "\n"


def main() -> None:
    for d in sorted(SKILLS.iterdir()):
        if not d.is_dir():
            continue
        if not (d / "patterns.md").exists():
            continue
        body = render_index(d)
        out = d / "index.md"
        out.write_text(body, encoding="utf-8")
        print(f"Wrote {out.relative_to(ROOT)}")
    write_global_skills_index()
    print(f"Wrote {(SKILLS / 'index.md').relative_to(ROOT)}")


if __name__ == "__main__":
    main()
