# HexVibe Context

## Project Goal
HexVibe is an **MCP Security Server** and **Active Sidecar** for secure coding runtime, backed by **500** documented patterns in `core/skills/` (including **INS** for Electron/VSTO/NSIS, **AAC** for agent/cloud automation, **SEC** for Cloud & Secrets, **DVS** for supply-chain hardening, **ITS** for integration resiliency, **NJS** for Node-Sentinel backend protection, and fortress-grade **INF/K8S/DOCK/NGX/SQD** infrastructure controls). Cursor rule budget is set for **500+** rules.

## Tech Stack
- Python (FastAPI, Django, SQLAlchemy)
- JavaScript/TypeScript (NestJS)
- Go, Java (Spring), Ruby (Rails)
- Keycloak
- Kubernetes/Helm
- Docker

## AI Workflow (Code Generation & Review)
- **For any stack**, use **`core/skills/<domain>/index.md`** first (stack summary, **Top threats**, full **pattern ID** TOC, **Verification** links to `core/gold-standard-testbed/`). Then apply **`core/skills/<domain>/patterns.md`** (Anti-Pattern vs Safe-Pattern rows). Every domain under `core/skills/` follows this layout. Optional HTTP smoke tests live in **`core/gold-standard-testbed/integration/`** (requires `HEXVIBE_TARGET_URL`; separate from the 335 static markers).
- **Before writing or suggesting code** in **Python, Go, JavaScript/TypeScript, Java, or Ruby**, open and align with the relevant domain (e.g. `core/skills/fastapi-async/`, `core/skills/python-django/`, `core/skills/go-core/`, `core/skills/nodejs-nestjs/`, `core/skills/java-spring/`, `core/skills/ruby-rails/`, `core/skills/advanced-agent-cloud/` for Playwright/Next.js/RQ/MinIO/egress automation, `core/skills/desktop-vsto-suite/` for Electron/VSTO/NSIS). Treat `patterns.md` as the contract for safe vs vulnerable patterns.
- **When you find a vulnerability** in analysis or review, **always output the pattern ID** using the marker form: `Vulnerable: <PREFIX>-<NNN>` (example: `Vulnerable: GO-032`). Tie remediation to the Safe-Pattern in the same table row.
- **For mixed-domain tasks**, combine skill orchestration weights (50/30/20 extension-trigger-semantic), prefer higher `security_priority` on score ties, and validate all claims through `run_check(...)`.

## Architecture Layers
1. Static Intelligence: Semgrep + TruffleHog for anti-pattern discovery in code.
2. Active Scanning: runtime detectors in `run_check` for Docker root/latest and "мясные" account patterns.
3. Resiliency & Integrity Checks: circuit-breaker/timeout/bulkhead anti-patterns, payment integrity controls, CSP/integrity gates, and key rotation posture checks.
4. Node-Sentinel Runtime Protection: Node.js backend controls for injection, IDOR/BOLA, event-loop safety, dependency integrity, stream/TLS safety, and memory hygiene.
5. Fortress Layer: deep audit of Kubernetes/Helm manifests and Squid/Nginx proxy configurations (capabilities, seccomp/AppArmor, rootfs/read-only, egress controls, TLS/profile hardening).
6. Infra & Supply Chain: Syft for SBOM/license compliance checks and policy gates.
7. Verification & Evidence: deterministic checks, RAG context, and structured evidence generation.
8. Reporting & Remediation: prioritize findings by risk, allow `ignore_finding`, and apply `apply_remediation` Safe-Fix where available.

## MCP Strategy
HexVibe v13.0 (Fortress) uses an All-in-One Docker MCP runtime (`hexvibe-ai:latest`) with Semgrep, TruffleHog, Syft and pre-warmed RAG cache.

## Interaction Schema
`Agent <-> MCP Security Server <-> HexVibe Core (500 rules)`

## Skill-based Integration via MCP
- Use `server/adapter.py` as the HexVibe MCP adapter for code agents.
- Agent behavior rules are auto-loaded from `.cursor/rules/` (`hexvibe-mcp.md`, `general-instructions.md`).
- `list_skills()` returns available skills with activation triggers to keep context loading selective.
- Runtime supports **20+ skills** with weighted orchestration and priority-aware tie-break.
- `get_skill_context(skill_id)` returns `index.md` + `patterns.md` for the target skill only.
- `run_check(path)` runs Semgrep against generated packs, conditionally runs Syft for license-compliance findings, runs TruffleHog with `server/config.yaml`, and applies active detectors (Docker and identity anti-patterns).
- `ignore_finding(metric_id, file_path, line_content, reason)` stores approved false positives in `.hexvibe-ignore.yaml`.
- `apply_remediation(metric_id, file_path)` applies Safe-Fix remediation from the metric's Safe-Pattern (deterministic where supported).
- Preflight readiness: `python server/adapter.py --smoke-test`; container self-check script: `scripts/internal-test.sh`.

## Project Map
- `core/skills/`: all security domains (`patterns.md`, `index.md`, `skill.json`).
- `core/core-rules/`: architecture and analysis workflow baselines.
- `core/semgrep-rules/`: generated Semgrep packs from `python scripts/sync_semgrep.py`.
- `core/gold-standard-testbed/`: marker corpus and detection matrix artifacts.
- `server/adapter.py`: MCP adapter entrypoint; `server/config.yaml`: TruffleHog custom config.
- `scripts/`: generators and validation scripts aligned to the new core layout.

