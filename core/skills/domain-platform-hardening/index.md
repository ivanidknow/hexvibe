# Domain Platform Hardening

## Stack overview

Hardening for mobile/desktop/runtime/infrastructure platform controls and operational guardrails.

## Top threats

- **Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists.**: 36 metrics (`PY-024`, `PY-027`, `CWE-400-PY`, `CWE-670-PY`)
- **Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering.**: 20 metrics (`NJS-017`, `NJS-018`, `NJS-033`, `NJS-021`)
- **Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input.**: 8 metrics (`CWE-114-CSH-PROCESS-START-RELATIVE`, `CWE-497-CSH-SENSITIVE-LOG`, `CWE-606-CSH-UNTRUSTED-LOOP-BOUND`, `CWE-114-CSH-DLL-SEARCH-ORDER`)
- **Canary + auto rollback on SLO breach.**: 1 metrics (`INF-216`)
- **Egress allowlist через NetworkPolicy/egress proxy.**: 1 metrics (`INF-207`)
- **Immutable config + signed deployment pipeline.**: 1 metrics (`INF-213`)
- **mTLS + authn/authz даже во внутреннем контуре.**: 1 metrics (`INF-217`)
- **Ввести dedup/throttle и escalation policy.**: 1 metrics (`INF-220`)
- **Ввести ResourceQuota и LimitRange.**: 1 metrics (`INF-214`)
- **Вводить maxReplicas + circuit breaker на upstream.**: 1 metrics (`INF-203`)
- **Включить `FLAG_SECURE` на чувствительных экранах.**: 1 metrics (`MOB-021`)
- **Включить service mesh mTLS/PKI policy.**: 1 metrics (`INF-210`)
- **Вынести персоналии в защищенный справочник и role mapping.**: 1 metrics (`INF-200`)
- **Генерировать и хранить SBOM + provenance attestation.**: 1 metrics (`INF-209`)
- **Для query-параметров всегда выполнять явное приведение к ожидаемому примитиву (`string/number/boolean`) и отклонять объекты/операторы.**: 1 metrics (`CWE-20-UNIVERSAL-TYPE-CONFUSION`)
- **Для динамического рендеринга избегать исполнения шаблонного кода: использовать статические шаблоны из доверенного каталога и передавать только данные через контекст.**: 1 metrics (`CWE-94-UNIVERSAL-NO-SANDBOX-TEMPLATE`)
- **Добавить PDB для сохранения SLO при обновлениях/сбоях.**: 1 metrics (`INF-204`)
- **Добавить startup probe с корректным timeout window.**: 1 metrics (`INF-206`)
- **Запрет privileged debug в prod namespace.**: 1 metrics (`INF-212`)
- **Запрет string-exec, передача данных через безопасный IPC.**: 1 metrics (`DSK-100`)
- **Изоляция узлов через taints/tolerations/nodeSelector.**: 1 metrics (`INF-219`)
- **Использовать `ipcMain.handle` + schema validation + authz.**: 1 metrics (`DSK-105`)
- **Использовать digest pinning + controlled updates.**: 1 metrics (`INF-208`)
- **Настроить readiness/liveness/startup probes.**: 1 metrics (`INF-205`)
- **Не давать внешнему параметру напрямую выбирать файл/модуль; применять фиксированный маппинг `ID -> Filename` и deny-by-default для неизвестных значений.**: 1 metrics (`CWE-98-UNIVERSAL-FILE-INFRA-CONTROL`)
- **Никогда не печатать токены, даже в debug.**: 1 metrics (`MOB-010`)
- **Обновление зависимости + hardening bootstrap.**: 1 metrics (`DSK-110`)
- **Обязательные CPU requests/limits по профилю сервиса.**: 1 metrics (`INF-201`)
- **Обязательные memory requests/limits и OOM policy.**: 1 metrics (`INF-202`)
- **Политика ротации и автоматический rollover.**: 1 metrics (`INF-211`)
- **Политика хранения/архивации security logs.**: 1 metrics (`INF-215`)
- **Применить baseline профили на namespace/service.**: 1 metrics (`INF-218`)
- **Удалить bypass, включить pinning/strict TLS validation.**: 1 metrics (`MOB-001`)

## Pattern catalog

Complete Anti-Pattern / Safe-Pattern definitions live in [`patterns.md`](patterns.md). The table below is a **table of contents** by metric ID.

| ID | Metric | Stack |
|---|---|---|
| `MOB-001` | Flutter TLS bypass | Удалить bypass, включить pinning/strict TLS validation. |
| `MOB-010` | Token leakage in debug mode | Никогда не печатать токены, даже в debug. |
| `MOB-021` | Missing UI privacy protection | Включить `FLAG_SECURE` на чувствительных экранах. |
| `DSK-100` | Electron remote code injection path | Запрет string-exec, передача данных через безопасный IPC. |
| `DSK-105` | Insecure IPC for sensitive actions | Использовать `ipcMain.handle` + schema validation + authz. |
| `DSK-110` | Old xlsx prototype pollution risk | Обновление зависимости + hardening bootstrap. |
| `NJS-017` | Dependency integrity gaps | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-018` | Header fingerprint leakage | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-033` | Weak TLS config | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `INF-200` | Hardcoded employee identities in notification routes | Вынести персоналии в защищенный справочник и role mapping. |
| `INF-201` | Missing CPU limits in workloads | Обязательные CPU requests/limits по профилю сервиса. |
| `INF-202` | Missing memory limits in workloads | Обязательные memory requests/limits и OOM policy. |
| `INF-203` | Unbounded worker autoscaling | Вводить maxReplicas + circuit breaker на upstream. |
| `INF-204` | No pod disruption budget | Добавить PDB для сохранения SLO при обновлениях/сбоях. |
| `INF-205` | Missing readiness probe | Настроить readiness/liveness/startup probes. |
| `INF-206` | Missing startup probe for heavy services | Добавить startup probe с корректным timeout window. |
| `INF-207` | No network egress policy | Egress allowlist через NetworkPolicy/egress proxy. |
| `INF-208` | Unpinned base image digest | Использовать digest pinning + controlled updates. |
| `INF-209` | Missing SBOM attestation in release flow | Генерировать и хранить SBOM + provenance attestation. |
| `INF-210` | Unencrypted internal traffic | Включить service mesh mTLS/PKI policy. |
| `INF-211` | No centralized secret rotation | Политика ротации и автоматический rollover. |
| `INF-212` | Privileged debug containers in production | Запрет privileged debug в prod namespace. |
| `INF-213` | Missing immutable config boundary | Immutable config + signed deployment pipeline. |
| `INF-214` | No resource quota per namespace | Ввести ResourceQuota и LimitRange. |
| `INF-215` | Missing audit retention policy | Политика хранения/архивации security logs. |
| `INF-216` | No rollback safety gate | Canary + auto rollback on SLO breach. |
| `INF-217` | Exposed admin endpoints internally without auth | mTLS + authn/authz даже во внутреннем контуре. |
| `INF-218` | Missing runtime seccomp/apparmor baseline | Применить baseline профили на namespace/service. |
| `INF-219` | No node taint/toleration isolation | Изоляция узлов через taints/tolerations/nodeSelector. |
| `INF-220` | Incident notification without rate control | Ввести dedup/throttle и escalation policy. |
| `PY-024` | Insecure httpx TLS config | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PY-027` | Unbounded pagination/query limits | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `NJS-021` | Missing request payload size limits (DoS risk) | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-030` | JSON Depth/Size Limits missing in body parsing | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `FTS-009` | Dependency Integrity Missing for third-party scripts | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-400-PY` | ReDoS in Python regex on unbounded user input | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-670-PY` | Race Condition in temporary file creation (predictable path) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-400-JS` | ReDoS in JavaScript regex against user input | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-670-JS` | Race Condition in file writes with predictable names | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-755-JS` | Unhandled rejection / await without try-catch in IPC handlers | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-295-PY` | TLS certificate validation disabled in Python SSLContext | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-297-PY` | Deprecated/weak TLS protocol versions in Python | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-295-JS-ENV` | Global TLS verification bypass via environment in Node.js | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-295-JS-REQ` | TLS validation disabled in https.request options | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-451-PY` | Clickjacking protection middleware missing in Django | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-1321-JS-JSON` | Prototype pollution risk after JSON.parse(untrusted) | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-362-PY` | Race Condition in async Python state updates | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-362-JS` | Race Condition in async Node.js critical sections | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-451-JS` | Missing CSP/Clickjacking headers in JS web stack | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-400-PY-RESOURCE` | Unreleased file/socket handles in Python loops/generators | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-772-JS-BUFFER` | Use of `Buffer.allocUnsafe()` without immediate full overwrite | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-174-PY-CANONICAL` | Missing final canonicalization/boundary check after Python input transformations | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-174-JS-CANONICAL` | Missing final canonicalization check after JS/Node normalization pipeline | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-116-PY-PARTIAL-ESCAPE` | Improper output encoding in Python: escaping only `<`/`>` but not attribute vectors | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-116-JS-PARTIAL-ESCAPE` | Improper output encoding in JS: partial replace allows `onerror`/`onload` attribute inj... | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-94-UNIVERSAL-NO-SANDBOX-TEMPLATE` | Dynamic template rendering without sandbox/isolation controls | Для динамического рендеринга избегать исполнения шаблонного кода: использовать статические шаблоны из доверенного каталога и передавать только данные через контекст. |
| `CWE-20-UNIVERSAL-TYPE-CONFUSION` | Missing input type validation/casting for query-critical fields (type confusion) | Для query-параметров всегда выполнять явное приведение к ожидаемому примитиву (`string/number/boolean`) и отклонять объекты/операторы. |
| `CWE-98-UNIVERSAL-FILE-INFRA-CONTROL` | External control of executable/loadable file selection without mapping | Не давать внешнему параметру напрямую выбирать файл/модуль; применять фиксированный маппинг `ID -> Filename` и deny-by-default для неизвестных значений. |
| `CWE-942-PLAYWRIGHT-WEBSEC` | Browser security bypass via Playwright insecure launch flags | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-295-PLAYWRIGHT-HTTPS` | TLS trust bypass in browser automation via `ignoreHTTPSErrors: true` | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-295-S3-MINIO-VERIFY` | Insecure TLS disable in MinIO/S3 clients (`verify=False`) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-942-S3-PUBLIC-ACL` | Public object ACL exposure in S3/MinIO operations | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-400-GIGAAM-UPLOAD-LIMITS` | Missing content-length/file size limits for audio upload endpoints (transcription) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-400-GIGAAM-HTTPX-TIMEOUT` | Missing `httpx` timeouts for transcription API calls (resource exhaustion risk) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-94-ELECTRON-WEBPREFS` | Insecure Electron BrowserWindow webPreferences (`nodeIntegration: true` / `contextIsola... | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-250-ELECTRON-REMOTE` | Unsafe usage of deprecated Electron `remote` module | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-94-NODE-EXEC-CONCAT` | Command injection risk in `child_process.exec/spawn` with user-influenced command conca... | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-295-BOTO3-VERIFY-FALSE` | Insecure TLS verification disabled in boto3 sessions/clients | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-284-BOTO3-PUBLIC-ACL` | Overly permissive S3 bucket ACL (`public-read/public-read-write`) via boto3 | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-295-BOTO3-PRESIGNED-TTL` | Excessive presigned URL lifetime (`ExpiresIn > 3600`) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-114-CSH-PROCESS-START-RELATIVE` | Unsafe process execution via relative binary path (`Process.Start("app.exe")`) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CWE-497-CSH-SENSITIVE-LOG` | Sensitive environment/exception disclosure in logs (`Environment.GetEnvironmentVariable... | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CWE-606-CSH-UNTRUSTED-LOOP-BOUND` | Untrusted input controls loop termination in unsafe/memory-copy contexts | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CWE-114-CSH-DLL-SEARCH-ORDER` | Missing DLL search order hardening in VSTO startup (`SetDllDirectory("")`/`SetDefaultDl... | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CWE-362-CSH-STATIC-ASYNC-RACE` | Race condition: writes to `static` fields inside async methods/event handlers without s... | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CWE-583-CSH-METADATA-ACL-TRUST` | Access control decisions based on mutable document metadata (`BuiltInDocumentProperties`) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CWE-912-CSH-ANTI-DEBUG-AUTH` | Anti-debug logic (`Debugger.IsAttached`/`Debug.Assert`) inside auth-critical flow | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CWE-749-CSH-SINGLETON-PUBLIC-HOOKS` | Public `event`/`Action` in singleton security classes allowing external state mutation | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `PLT-001` | Создание temp-файла в общем каталоге с предсказуемым именем (CWE-379) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PLT-002` | Утечка памяти: повторный `malloc` без `free` в C-extension glue (CWE-401) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PLT-003` | Двойное освобождение одного указателя (CWE-415) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PLT-004` | Use-after-free в callback после async (CWE-416) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PLT-005` | Плагин получает доступ к объекту вне его security-контекста (CWE-668) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PLT-006` | Неправильная инициализация ресурса до проверки прав (CWE-403) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PLT-007` | Асимметричное потребление ресурсов при парсинге входа (CWE-405) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PLT-008` | Неверное преобразование типа в security check (CWE-704) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PLT-009` | Чтение за пределами выделенного буфера в shim (CWE-125) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PLT-010` | Отсутствие обработки ошибки при security decision (CWE-390) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PLT-011` | Раскрытие чувствительного различия ошибок (CWE-203) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PLT-012` | Целочисленное переполнение при выделении структуры (CWE-189) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PLT-013` | Некавыченный путь поиска при `subprocess` (CWE-428) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PLT-014` | Нулевой pointer dereference после guard (CWE-476) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PLT-015` | Неправильное сравнение указателей вместо содержимого (CWE-581) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PLT-016` | Некорректные права по умолчанию на конфиг с секретами (CWE-276) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |

## Verification

**Verification:** Check the gold testbed file(s) below for `Vulnerable: <ID>` markers (static Semgrep + `detection-matrix.md` ground truth).

- [`gold-standard-testbed/gap_fill_vulnerable.py`](../gold-standard-testbed/gap_fill_vulnerable.py)

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

