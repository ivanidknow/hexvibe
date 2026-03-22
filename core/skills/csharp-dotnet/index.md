# C# / .NET

## Stack overview

**ASP.NET** / .NET patterns: Roslyn, process execution, XML, cookies, crypto, and redirects. Metrics are prefixed **`CSH`**.

## Top threats

- Code/command injection and unsafe reflection (`CSH-001`–`CSH-008`).
- Deserialization and XXE (`CSH-009`, `CSH-010`).
- Secrets, cookies, TLS (`CSH-011`–`CSH-015`, `CSH-016`).

## Pattern catalog

Complete Anti-Pattern / Safe-Pattern definitions live in [`patterns.md`](patterns.md). The table below is a **table of contents** by metric ID.

| ID | Metric | Stack |
|---|---|---|
| `CSH-001` | C# Code Injection: `CSharpScript.EvaluateAsync` на пользовательском вводе | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-002` | Command Injection: `Process.Start` со строкой аргументов | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-003` | Shell Execute Injection: `UseShellExecute=true` с пользовательским вводом | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-004` | Unsafe Reflection: `Type.GetType` из user input | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-005` | Dynamic Invoke Injection: `GetMethod(...).Invoke` без allowlist | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-006` | SQL Fragment Injection в `ORDER BY` | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-007` | Roslyn Compilation of Untrusted Code | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-008` | JavaScript Engine Injection (Jint/ClearScript) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-009` | Небезопасная десериализация | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-010` | XXE Injection | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-011` | Insecure Cookie Flags | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-012` | Hardcoded Secrets | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-013` | Weak Crypto | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-014` | Open Redirect | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-015` | Certificate Validation Bypass | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-016` | Weak Password Hashing | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-017` | Office HTML Injection в Outlook/Excel формулы | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-018` | VSTO macro-equivalent command execution | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-019` | Banned BinaryFormatter Deserialize | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-020` | Insecure DataSet.ReadXml from untrusted input | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-021` | Unsafe P/Invoke marshaling | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-022` | Insecure Assembly.Load from path/user input | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-023` | ASP.NET Mass Assignment (Entity binding) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-024` | Unsafe AutoMapper profile exposing privileged fields | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-025` | JWT validation gaps in .NET auth | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-026` | OAuth redirect URI not validated | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-027` | Insecure file upload without extension/content checks | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-028` | Path traversal in static file/document download | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-029` | Missing anti-forgery on state-changing MVC actions | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-030` | Insecure session config in .NET 4.8 | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-031` | Json.NET TypeNameHandling unsafe mode | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-032` | ASP.NET request validation disabled | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-033` | Weak TLS protocol negotiation | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-034` | Insecure random via System.Random for secrets | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-035` | Sensitive data in logs/debug output | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-036` | LDAP injection via unescaped filter | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-037` | Regex DoS in server validation | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-038` | XML signature validation bypass | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-039` | gRPC auth metadata not validated | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-040` | GraphQL over-posting of sensitive fields | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-041` | Entity Framework FromSqlRaw injection | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-042` | Open telemetry export without data scrubbing | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-043` | WebClient legacy insecure usage | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-044` | Hardcoded service account credentials | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-045` | Missing object-level authorization in API | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-046` | Unsafe cleanup deletion with user-supplied path | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-047` | VSTO/.NET 4.8 unsafe `BinaryFormatter.Deserialize` usage | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-048` | Dynamic assembly loading from network paths (UNC/URL) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-049` | SSRF C#: `HttpClient` к AWS metadata IP (CWE-918) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-050` | SSRF C#: `WebRequest` к GCP metadata host (CWE-918) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-051` | SSRF C#: `RestSharp` к link-local metadata (CWE-918) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-052` | SSRF C#: `SocketsHttpHandler` без фильтра IMDS (CWE-918) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CSH-053` | Paladin: non-constant-time compare for password/token hash (CWE-613) | Replace `==` on secrets with `CryptographicOperations.FixedTimeEquals` or verified KDF APIs only. |
| `CSH-054` | Paladin: JWT `ValidateLifetime` disabled | Enable lifetime validation and align clock skew with token issuer SLA. |
| `CSH-055` | Paladin: JWT `ClockSkew` zeroed (clock tolerance removed) | Avoid `TimeSpan.Zero` unless IdP mandates; document skew rationale. |
| `CSH-056` | Paladin: `Path.GetTempFileName()` без явных ACL (CWE-377) | Create temp files under app-controlled dir with explicit ACL, not default shared temp. |
| `CSH-057` | Paladin: `Process.Start` путь с пробелами без кавычек (CWE-428) | Always quote/structure paths with spaces; avoid single-string overloads for untrusted paths. |
| `CSH-058` | Paladin: `Registry` ImagePath без кавычек при пробелах (CWE-428) | Quote service binary paths in registry; validate against allowlist. |

## Verification

**Verification:** Check the gold testbed file(s) below for `Vulnerable: <ID>` markers (static Semgrep + `detection-matrix.md` ground truth).

- [`gold-standard-testbed/multi_lang_vulnerable/csharp_vulnerable.cs`](../gold-standard-testbed/multi_lang_vulnerable/csharp_vulnerable.cs)

After changing [`patterns.md`](patterns.md), run from the repo root:

```bash
python scripts/sync_semgrep.py
```

## Workflow: Recon → Scan → Verify

### 1) Recon
- Map entrypoints, data flows, and trust boundaries for this stack.
- Identify which metrics in [`patterns.md`](patterns.md) apply to the code under review.

### 2) Scan
- Run Semgrep with `semgrep-rules/<skill>.yaml` (generated) and correlate with Anti-Patterns.
- Eliminate findings that cannot bind to a metric row.

### 3) Verify
- Confirm markers or scanner hits for touched IDs in the gold testbed when adding metrics.
- Emit findings as `Vulnerable: <PREFIX>-<NNN>` in written reviews.

