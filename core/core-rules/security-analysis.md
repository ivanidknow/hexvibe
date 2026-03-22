# HexVibe Security Analysis Workflow

When performing security analysis in this repository, follow this order:

1) Start with static scanners through MCP-managed Docker containers:
- Semgrep
- TruffleHog
- KICS
- Syft

2) Correlate scanner output with anti-pattern knowledge. **Start from each domain `index.md`** (stack summary, top threats, full ID table of contents, verification links). **Authoritative metrics** are the rows in that domain’s **`patterns.md`** (Anti-Pattern / Safe-Pattern / source).

- [`skills/advanced-agent-cloud/index.md`](../skills/advanced-agent-cloud/index.md) · [`patterns.md`](../skills/advanced-agent-cloud/patterns.md)
- [`skills/app-logic/index.md`](../skills/app-logic/index.md) · [`patterns.md`](../skills/app-logic/patterns.md)
- [`skills/auth-keycloak/index.md`](../skills/auth-keycloak/index.md) · [`patterns.md`](../skills/auth-keycloak/patterns.md)
- [`skills/browser-agent/index.md`](../skills/browser-agent/index.md) · [`patterns.md`](../skills/browser-agent/patterns.md)
- [`skills/csharp-dotnet/index.md`](../skills/csharp-dotnet/index.md) · [`patterns.md`](../skills/csharp-dotnet/patterns.md)
- [`skills/fastapi-async/index.md`](../skills/fastapi-async/index.md) · [`patterns.md`](../skills/fastapi-async/patterns.md)
- [`skills/go-core/index.md`](../skills/go-core/index.md) · [`patterns.md`](../skills/go-core/patterns.md)
- [`skills/infra-k8s-helm/index.md`](../skills/infra-k8s-helm/index.md) · [`patterns.md`](../skills/infra-k8s-helm/patterns.md)
- [`skills/desktop-vsto-suite/index.md`](../skills/desktop-vsto-suite/index.md) · [`patterns.md`](../skills/desktop-vsto-suite/patterns.md)
- [`skills/java-spring/index.md`](../skills/java-spring/index.md) · [`patterns.md`](../skills/java-spring/patterns.md)
- [`skills/nodejs-nestjs/index.md`](../skills/nodejs-nestjs/index.md) · [`patterns.md`](../skills/nodejs-nestjs/patterns.md)
- [`skills/observability/index.md`](../skills/observability/index.md) · [`patterns.md`](../skills/observability/patterns.md)
- [`skills/python-django/index.md`](../skills/python-django/index.md) · [`patterns.md`](../skills/python-django/patterns.md)
- [`skills/ruby-rails/index.md`](../skills/ruby-rails/index.md) · [`patterns.md`](../skills/ruby-rails/patterns.md)
- [`skills/license-compliance/index.md`](../skills/license-compliance/index.md) · [`patterns.md`](../skills/license-compliance/patterns.md)
- [`skills/ru-regulatory/index.md`](../skills/ru-regulatory/index.md) · [`patterns.md`](../skills/ru-regulatory/patterns.md)
- [`skills/cloud-secrets/index.md`](../skills/cloud-secrets/index.md) · [`patterns.md`](../skills/cloud-secrets/patterns.md)

Optional **HTTP integration** pytest modules (live API, not part of the 300-rule matrix) live under [`gold-standard-testbed/integration/`](../gold-standard-testbed/integration/README.md).

3) Filter false positives deterministically:
- Require direct evidence matching `skills/*/patterns.md`.
- Drop findings that are not reachable/used in repository context.
- Retain only findings with clear, reproducible threat paths.

4) Argue risks using architecture controls from `core-rules/architecture.md`.
- Prefer architecture-backed evidence over heavy DAST unless explicitly requested.

5) Mandatory metric enforcement:
- When writing, proposing, or reviewing code, always check ID-based metrics in `skills/*/patterns.md` (300 patterns total with SEC/LIC/RRC domains; stacks include **INS** for Electron/VSTO/NSIS, **AAC** for agent/cloud automation, **SEC** for cloud/secrets controls, DJA for Django, NST for NestJS, plus FAS, GO, JAVA, RUBY, etc.).
- If any anti-pattern is violated (for example `FAS-013`, `AK-001`, `INF-5.2.4`, `BIZ-011`, `LOG-011`, `DJA-011`, `NST-014`, `AAC-001`, `INS-003`), warn immediately.
- **When reporting a finding, always include the pattern ID in the standard form** `Vulnerable: <PREFIX>-<NNN>` (e.g. `Vulnerable: GO-032`), matching how markers appear in the gold testbed and Semgrep packs.
- Provide the corresponding Safe-Pattern from the same metric entry.
- Do not approve violating code without explicitly listing violated metric IDs.

6) Training corpus filtering:
- Ignore `skills/*/patterns.md` and `gold-standard-testbed/` in project-level scanner verdicts.
- Treat these paths as intentionally vulnerable training corpus.
