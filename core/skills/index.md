# HexVibe Skills Index

Central catalog of all security domains under `core/skills/`.

| Domain | Path | Rules | Primary Stack | Stack Summary |
|---|---|---:|---|---|
| Advanced Agent Cloud | `core/skills/advanced-agent-cloud/` | 44 | Agent/Browser | Agent/Browser:44 |
| App Logic | `core/skills/app-logic/` | 21 | Application Logic | Application Logic:21 |
| Auth Keycloak | `core/skills/auth-keycloak/` | 21 | Identity/OIDC | Identity/OIDC:21 |
| Browser Agent | `core/skills/browser-agent/` | 13 | Browser Automation | Browser Automation:13 |
| Cloud Secrets | `core/skills/cloud-secrets/` | 17 | Cloud/Secrets | Cloud/Secrets:17 |
| Csharp Dotnet | `core/skills/csharp-dotnet/` | 58 | .NET/C# | .NET/C#:58 |
| Desktop Vsto Suite | `core/skills/desktop-vsto-suite/` | 152 | Electron/Desktop/.NET | Electron/Desktop/.NET:152 |
| Devops Security | `core/skills/devops-security/` | 21 | DevOps/Supply Chain | DevOps/Supply Chain:21 |
| Domain Access Management | `core/skills/domain-access-management/` | 56 | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists.:19, Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering.:14, Cache key по subject+scope+tenant+ttl.:1 |
| Domain Data Privacy | `core/skills/domain-data-privacy/` | 46 | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering.:19, Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists.:17, Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input.:3 |
| Domain Input Validation | `core/skills/domain-input-validation/` | 156 | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists.:75, Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering.:66, Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input.:4 |
| Domain Platform Hardening | `core/skills/domain-platform-hardening/` | 94 | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists.:36, Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering.:20, Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input.:8 |
| Fastapi Async | `core/skills/fastapi-async/` | 35 | Python/FastAPI | Python/FastAPI:35 |
| Go Core | `core/skills/go-core/` | 40 | Go | Go:40 |
| Infra K8S Helm | `core/skills/infra-k8s-helm/` | 90 | Kubernetes/Infra | Kubernetes/Infra:90 |
| Integration Security | `core/skills/integration-security/` | 30 | Integration/API | Integration/API:30 |
| Java Spring | `core/skills/java-spring/` | 20 | Java/Spring | Java/Spring:20 |
| License Compliance | `core/skills/license-compliance/` | 10 | Compliance/License | Compliance/License:10 |
| Nodejs Nestjs | `core/skills/nodejs-nestjs/` | 26 | Node.js/NestJS | Node.js/NestJS:26 |
| Observability | `core/skills/observability/` | 20 | Observability | Observability:20 |
| Ru Regulatory | `core/skills/ru-regulatory/` | 26 | Compliance/Regulatory | Compliance/Regulatory:26 |
| Ruby Rails | `core/skills/ruby-rails/` | 20 | Ruby/Rails | Ruby/Rails:20 |

**Total unique rules:** 1000
**Total rows across domains:** 1016

## Standards coverage (compliance layer)

Aggregated from `CWE-*` tokens in `patterns.md` via `scripts/compliance_layer.py` (OWASP Top 10 **2021** categories; representative MITRE ATT&CK **Enterprise** techniques; NIST SSDF PO fields are proxy counts).

| Standard | Category | Patterns (rules tagged) | Status |
|---|---|---:|---|
| OWASP Top 10 (2021) | A01 | 15 | Covered |
| OWASP Top 10 (2021) | A02 | 16 | Covered |
| OWASP Top 10 (2021) | A03 | 106 | Covered |
| OWASP Top 10 (2021) | A04 | 434 | Covered |
| OWASP Top 10 (2021) | A05 | 194 | Covered |
| OWASP Top 10 (2021) | A06 | 11 | Covered |
| OWASP Top 10 (2021) | A07 | 95 | Covered |
| OWASP Top 10 (2021) | A08 | 24 | Covered |
| OWASP Top 10 (2021) | A09 | 33 | Covered |
| OWASP Top 10 (2021) | A10 | 73 | Covered |
| MITRE ATT&CK (Enterprise) | T1005 | 26 | Mapped |
| MITRE ATT&CK (Enterprise) | T1055 | 10 | Mapped |
| MITRE ATT&CK (Enterprise) | T1059 | 79 | Mapped |
| MITRE ATT&CK (Enterprise) | T1059.004 | 33 | Mapped |
| MITRE ATT&CK (Enterprise) | T1059.007 | 20 | Mapped |
| MITRE ATT&CK (Enterprise) | T1078 | 84 | Mapped |
| MITRE ATT&CK (Enterprise) | T1083 | 10 | Mapped |
| MITRE ATT&CK (Enterprise) | T1098 | 5 | Mapped |
| MITRE ATT&CK (Enterprise) | T1110 | 3 | Mapped |
| MITRE ATT&CK (Enterprise) | T1189 | 13 | Mapped |
| MITRE ATT&CK (Enterprise) | T1190 | 701 | Mapped |
| MITRE ATT&CK (Enterprise) | T1195 | 21 | Mapped |
| MITRE ATT&CK (Enterprise) | T1195.001 | 10 | Mapped |
| MITRE ATT&CK (Enterprise) | T1204 | 24 | Mapped |
| MITRE ATT&CK (Enterprise) | T1499 | 10 | Mapped |
| MITRE ATT&CK (Enterprise) | T1548 | 3 | Mapped |
| MITRE ATT&CK (Enterprise) | T1550 | 5 | Mapped |
| MITRE ATT&CK (Enterprise) | T1552 | 21 | Mapped |
| MITRE ATT&CK (Enterprise) | T1556 | 3 | Mapped |
| MITRE ATT&CK (Enterprise) | T1562 | 23 | Mapped |
| NIST SSDF (proxy) | PO.1 | 1000 | Indicative |
| NIST SSDF (proxy) | PO.3 | 35 | Indicative |
| **HexVibe rules** | Total IDs in matrix | 1000 | OK |
| **Compliance tags** | Rules with OWASP+MITRE tags | 1000 | See `rule-compliance-map.json` |
