# HexVibe v1.0 — Cognitive AppSec Guardrail

[![Platform](https://img.shields.io/badge/platform-AI--Security-blueviolet)](#capabilities)
[![Architecture](https://img.shields.io/badge/arch-Threat%20Modeling%20Enabled-blue)](core/skills/)
[![Compliance](https://img.shields.io/badge/compliance-Enterprise%20Ready-success)](core/skills/)
[![Rules Count](https://img.shields.io/badge/rules-1000%20patterns-blue)](core/skills/index.md)
[![Status](https://img.shields.io/badge/status-Production%20Ready-orange)](#development--extension)

**HexVibe** is an MCP security server designed for full automation of Security Code Reviews and protection of the generative development lifecycle using a **Cognitive Guardrail**. The system ensures that only verified findings with high trust (confidence_score >= 0.8) reach the final logs.

The current ruleset is regression-locked at **1000/1000 HIT** within the `core/gold-standard-testbed/` environment.

---

## Architecture Flow

(Insert Mermaid Diagram here: flowchart TD A[Developer] --> B(HexVibe) --> C{Cognitive Engine} --> D[Verified Report])

---

## Quick Start

### 1) Build & Sync
Execute in your terminal:
bash scripts/docker-publish.sh
python scripts/sync_semgrep.py

### 2) Run (Docker)
docker run -i --rm -v "${PWD}:/app" hexvibe-ai:latest

### 3) IDE Integration
* **Cursor**: Settings -> Features -> MCP -> Add server. Name: HexVibe, Type: command, Command: docker run -i --rm -v "${PWD}:/app" hexvibe-ai:latest.
* **Claude Desktop**: Copy settings from mcp-deployment.json into your MCP configuration file.

### 4) Verification
Ask the agent: "HexVibe, confirm current baseline." Expected response: confirmation of 1000 patterns and v1.0 cognitive metadata.

---

## Cognitive Guardrail

Implemented in server/cognitive_engine.py. The analysis process is divided into three phases:
* **Phase 1 — Context Research**: Analysis of signals within files and project manifests (package.json, requirements.txt, pyproject.toml) with recursive search to the repository root.
* **Phase 2 — Trust Analysis**: Base scoring with a +0.2 bonus if code behavior deviates from the stack declared in manifests. Strict exclusions (HARD EXCLUSIONS) and a precedent database are applied to suppress noise.
* **Phase 3 — Self-critique**: Final verification via extra.cognitive.self_critique to confirm real attack chains (attack_path_concrete: user -> sink).

---

## Official Baseline

| Metric | Value |
| :--- | :--- |
| Rule IDs | 1000 |
| Accuracy (Gold matrix) | 1000 / 1000 HIT |
| Security Domains | 22 |
| CWE Coverage (patterns) | >= 138 |
| Auto-remediation (Autofix) | 1000 / 1000 |

---

## Capabilities

* **Interactive Threat Modeling (STRIDE)**: Automated generation of a threat model at the start of every review. The system independently identifies 5 priority attack vectors (Infrastructure & Business Logic) specific to the project architecture and verifies their presence in the code.
* **Architectural Cross-check**: A unique verification mechanism that maps theoretical threats to real signals in the repository. Each finding is assigned a status: **[CONFIRMED]** or **[REQUIRES VERIFICATION]**, simulating an expert architect's conclusion.
* **Cognitive Guardrail**: A three-phase analysis (research -> scoring -> self-critique) that filters false positives and suppresses noise based on the enterprise environment context.
* **Smart Autofix (1000/1000)**: The system not only finds vulnerabilities but also provides context-aware fixes for all 1000 patterns, neutralizing anti-patterns directly during AI code generation.
* **Advanced Stack Coverage**: Specialized protection for high-risk areas: IPC isolation, API security, Prompt Leakage in AI SDKs, and secure document processing.
* **MCP + Docker Orchestration**: Seamless integration of Semgrep, TruffleHog, and Syft. The server/adapter.py module manages the full scan lifecycle.

---

## Use Cases

### Scenario A: Runtime AI Guardrail
Use HexVibe as a "live fuse" while an AI assistant generates code.
* **How it works**: The system neutralizes vulnerabilities on the fly (e.g., attempts to hardcode keys or make insecure API calls).
* **Prompt**: "Write a function for data exchange between application components. Use HexVibe to check security and automatically apply Autofix for any violations."

### Scenario B: Security Review
Automating the work of an AppSec Architect to check the entire repository before release.
* **How it works**: Generation of a STRIDE threat model, searching for logical flaws, and confirming their presence in the code with **[CONFIRMED]** statuses.
* **Prompt**:
"Analyze the security of the **[Project Name]** project via run_security_review in the context of the production environment.

Requirements for the report:
1. **Threat Modeling**: Generate a full Markdown report starting with Section 0 (Threat Model).
2. **Cross-check**: For each architectural threat, indicate the verification status in the code: **[CONFIRMED]** or **[REQUIRES VERIFICATION]**.
3. **Filtering**: Apply Cognitive Guardrail to exclude infrastructure false positives.
4. **Result**: Save the final report to security_review_latest.md."

---

## Development & Extension

* **Modifying Rules**: Edit patterns.md in the appropriate domain directory (core/skills/domain/) and run python scripts/sync_semgrep.py to rebuild the ruleset.
* **Extending Testbed**: Add new PoCs in core/gold-standard-testbed/ with markers Vulnerable: PREFIX-NNN for regression testing.
* **Custom Fixes**: HexVibe maps metric IDs to apply_remediation calls via the MCP interface for rapid vulnerability patching.

---

## Security & compliance stance

Documentation and rules use **Enterprise Compliance** and **high-security** terminology: data protection, residency, cryptography, and infrastructure controls are described in vendor-neutral language suitable for open-source use.

## Security Principles

Mark PoCs with the tag Vulnerable: PREFIX-NNN (label); use these same IDs when conducting reviews. Shipping code with unpatched violations of known metrics is not allowed without an officially documented exception.