# HexVibe Skills Index

Central catalog of all security domains under `core/skills/`.

| Domain | Path | Rules | Primary Stack | Stack Summary |
|---|---|---:|---|---|
| Advanced Agent Cloud | `core/skills/advanced-agent-cloud/` | 44 | Agent/Browser | Agent/Browser:44 |
| App Logic | `core/skills/app-logic/` | 21 | Application Logic | Application Logic:21 |
| Auth Keycloak | `core/skills/auth-keycloak/` | 44 | Identity/OIDC | Identity/OIDC:44 |
| Browser Agent | `core/skills/browser-agent/` | 13 | Browser Automation | Browser Automation:13 |
| Cloud Secrets | `core/skills/cloud-secrets/` | 17 | Cloud/Secrets | Cloud/Secrets:17 |
| Csharp Dotnet | `core/skills/csharp-dotnet/` | 268 | .NET/C# | .NET/C#:268 |
| Desktop Vsto Suite | `core/skills/desktop-vsto-suite/` | 152 | Electron/Desktop/.NET | Electron/Desktop/.NET:152 |
| Devops Security | `core/skills/devops-security/` | 21 | DevOps/Supply Chain | DevOps/Supply Chain:21 |
| Domain Access Management | `core/skills/domain-access-management/` | 56 | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists.:19, Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering.:14, Cache key по subject+scope+tenant+ttl.:1 |
| Domain Data Privacy | `core/skills/domain-data-privacy/` | 46 | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering.:19, Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists.:17, Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input.:3 |
| Domain Input Validation | `core/skills/domain-input-validation/` | 156 | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists.:75, Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering.:66, Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input.:4 |
| Domain Platform Hardening | `core/skills/domain-platform-hardening/` | 94 | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists.:36, Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering.:20, Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input.:8 |
| Ds Ml Security | `core/skills/ds-ml-security/` | 135 | Generic | Generic:135 |
| Fastapi Async | `core/skills/fastapi-async/` | 336 | Python/FastAPI | Python/FastAPI:336 |
| Frontend React | `core/skills/frontend-react/` | 224 | Generic | Generic:224 |
| Go Core | `core/skills/go-core/` | 270 | Go | Go:270 |
| Hft Cpp Security | `core/skills/hft-cpp-security/` | 35 | Generic | Generic:35 |
| Infra K8S Helm | `core/skills/infra-k8s-helm/` | 275 | Kubernetes/Infra | Kubernetes/Infra:275 |
| Integration Security | `core/skills/integration-security/` | 130 | Integration/API | Integration/API:130 |
| Java Enterprise | `core/skills/java-enterprise/` | 812 | Generic | Generic:812 |
| Java Spring | `core/skills/java-spring/` | 29 | Java/Spring | Java/Spring:29 |
| License Compliance | `core/skills/license-compliance/` | 10 | Compliance/License | Compliance/License:10 |
| Mobile Security | `core/skills/mobile-security/` | 40 | Generic | Generic:40 |
| Nodejs Nestjs | `core/skills/nodejs-nestjs/` | 286 | Node.js/NestJS | Node.js/NestJS:286 |
| Observability | `core/skills/observability/` | 20 | Observability | Observability:20 |
| Php Security | `core/skills/php-security/` | 200 | Generic | Generic:200 |
| Ru Regulatory | `core/skills/ru-regulatory/` | 26 | Compliance/Regulatory | Compliance/Regulatory:26 |
| Ruby Rails | `core/skills/ruby-rails/` | 20 | Ruby/Rails | Ruby/Rails:20 |
| Rust Security | `core/skills/rust-security/` | 150 | Generic | Generic:150 |

**Total unique rules:** 3870
**Total rows across domains:** 3930

## Standards coverage (Paladin compliance layer)

Aggregated from `CWE-*` tokens in `patterns.md` via `scripts/compliance_layer.py` (OWASP Top 10 **2021** categories; representative MITRE ATT&CK **Enterprise** techniques; NIST SSDF PO fields are proxy counts).

| Standard | Category | Patterns (rules tagged) | Status |
|---|---|---:|---|
| OWASP Top 10 (2021) | A01 | 505 | Covered |
| OWASP Top 10 (2021) | A02 | 110 | Covered |
| OWASP Top 10 (2021) | A03 | 422 | Covered |
| OWASP Top 10 (2021) | A04 | 1851 | Covered |
| OWASP Top 10 (2021) | A05 | 325 | Covered |
| OWASP Top 10 (2021) | A06 | 34 | Covered |
| OWASP Top 10 (2021) | A07 | 184 | Covered |
| OWASP Top 10 (2021) | A08 | 336 | Covered |
| OWASP Top 10 (2021) | A09 | 57 | Covered |
| OWASP Top 10 (2021) | A10 | 197 | Covered |
| MITRE ATT&CK (Enterprise) | T1005 | 140 | Mapped |
| MITRE ATT&CK (Enterprise) | T1055 | 212 | Mapped |
| MITRE ATT&CK (Enterprise) | T1059 | 286 | Mapped |
| MITRE ATT&CK (Enterprise) | T1059.004 | 237 | Mapped |
| MITRE ATT&CK (Enterprise) | T1059.007 | 193 | Mapped |
| MITRE ATT&CK (Enterprise) | T1078 | 132 | Mapped |
| MITRE ATT&CK (Enterprise) | T1083 | 48 | Mapped |
| MITRE ATT&CK (Enterprise) | T1098 | 457 | Mapped |
| MITRE ATT&CK (Enterprise) | T1110 | 15 | Mapped |
| MITRE ATT&CK (Enterprise) | T1189 | 65 | Mapped |
| MITRE ATT&CK (Enterprise) | T1190 | 2391 | Mapped |
| MITRE ATT&CK (Enterprise) | T1195 | 117 | Mapped |
| MITRE ATT&CK (Enterprise) | T1195.001 | 76 | Mapped |
| MITRE ATT&CK (Enterprise) | T1204 | 229 | Mapped |
| MITRE ATT&CK (Enterprise) | T1499 | 13 | Mapped |
| MITRE ATT&CK (Enterprise) | T1548 | 3 | Mapped |
| MITRE ATT&CK (Enterprise) | T1550 | 18 | Mapped |
| MITRE ATT&CK (Enterprise) | T1552 | 122 | Mapped |
| MITRE ATT&CK (Enterprise) | T1556 | 40 | Mapped |
| MITRE ATT&CK (Enterprise) | T1562 | 44 | Mapped |
| NIST SSDF (proxy) | PO.1 | 4020 | Indicative |
| NIST SSDF (proxy) | PO.3 | 370 | Indicative |
| **HexVibe rules** | Total IDs in matrix | 4020 | OK |
| **Compliance tags** | Rules with OWASP+MITRE tags | 4020 | See `rule-compliance-map.json` |
