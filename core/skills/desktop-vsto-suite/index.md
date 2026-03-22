# Desktop & Office Integration Suite

## Stack overview

**Electron** desktop shells (renderer hardening, IPC), **.NET / VSTO** Office add-ins (legacy deserialization, XML, secrets in config), **NSIS** installers, and **document / AI client** pipelines: **xlsx** (SheetJS), **docx**/PizZip, **mammoth**, **pdfjs-dist**, **word-extractor**, **OpenAI SDK** responses, and **main-process** hardening (`nodeIntegration: false`, `contextIsolation: true`, `senderFrame` checks). Metrics are prefixed **`INS`**.

## Top threats

- **Renderer compromise** via disabled isolation or Node in the page (`INS-001`, `INS-002`).
- **Remote code execution** through IPC bridges (`INS-003`).
- **Deserialization and XXE** in legacy .NET stacks (`INS-004`, `INS-005`).
- **Document chain:** XXE/zip-bomb/Excel formula injection (`INS-072`…`INS-091`, CWE-611/409/1236).
- **OpenAI integration:** unvalidated structured output and prompt logging (`INS-092`…`INS-099`, CWE-1027/1109/201).
- **Electron runtime:** explicit webPreferences, IPC sender validation (`INS-100`…`INS-110`).
- **Installer DLL hijacking** (`INS-006`) and **cleartext credentials** (`INS-007`).

## Pattern catalog

Complete Anti-Pattern / Safe-Pattern definitions live in [`patterns.md`](patterns.md). The table below is a **table of contents** by metric ID.

| ID | Metric | Stack |
|---|---|---|
| `INS-001` | Electron Insecure Content Isolation | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-002` | Electron Node Integration Leak | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-003` | Electron Insecure IPC | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-004` | .NET 4.8 / VSTO Legacy Deserialization | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-005` | VSTO Insecure XML | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-006` | NSIS DLL Hijacking | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-007` | VSTO Cleartext Password in Config | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-008` | Electron Production Debugging | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-009` | Unsafe .NET deserialization in desktop stack (BinaryFormatter/JavaScriptSerializer/XmlS... | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-010` | Dynamic assembly/type loading from untrusted concatenated input | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-011` | Unsafe native library loading without secure search path controls | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-012` | XXE risk: XmlDocument/XmlTextReader without `XmlResolver = null` | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-013` | Weak cryptography in .NET (`MD5`, `SHA1Managed`, `DESCryptoServiceProvider`) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-014` | TOCTOU file race (`Check then Open`) in `System.IO` | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-015` | Unsafe impersonation lifecycle: `WindowsIdentity.Impersonate()` without guaranteed `Und... | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-016` | Unsafe memory operations: `stackalloc`/pointer arithmetic without bounds checks | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-017` | Integer overflow risk in buffer/array size calculations outside `checked` blocks | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-018` | Resource lifecycle leak: missing `Dispose`/`using` for `SafeHandle`, `AutoResetEvent`, ... | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-019` | Registry operation driven by untrusted key/value input | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-020` | Dangerous locking primitives (`lock(this)`, `lock(typeof(...))`, `lock("string")`) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-021` | Unmanaged memory allocation without guaranteed `FreeHGlobal` in `finally` | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-022` | IPC object without explicit security descriptor (`PipeSecurity`/`MutexSecurity`) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-023` | Untrusted pipe name construction via string concatenation | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-024` | Unsafe handle passing to extern methods without trust validation | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-025` | Dangerous native interop functions imported via `[DllImport]` (`strcpy`, `strcat`, `gets`) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-026` | Reflection-based instance creation from untrusted type names | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-027` | Sensitive secrets stored in immutable `string` objects in memory | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-028` | Exception swallowing: empty `catch { }` without logging or rethrow | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-029` | Unchecked WinAPI return codes (`BOOL`/`HRESULT`) from `[DllImport]` calls | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-030` | COM object lifecycle leak: missing `Marshal.ReleaseComObject()` in `try/finally` | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-031` | Hardcoded cryptographic keys in `AesManaged` / `RSACryptoServiceProvider` initialization | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-032` | Insecure random generation for crypto material using `System.Random` | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-033` | Weak RSA key size (<2048 bits) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-034` | Hardcoded `AesManaged` Key/IV byte arrays in code | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-035` | `System.Random` used for auth token or cryptographic salt generation | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-036` | Unsafe dynamic JSON deserialization: `JsonConvert.DeserializeObject<dynamic>(...)` with... | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-037` | `XmlDocument.LoadXml()` without DTD/entities hardening | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-038` | `WebBrowser.Navigate(userUrl)` without strict protocol allowlist (https only) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-039` | Debug-only bypass methods disable SSL/license checks via `[Conditional("DEBUG")]` | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-040` | Accessing `Globals.ThisAddIn.Application` from background thread without marshaling/invoke | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-041` | Missing Electron CSP `frame-ancestors 'none'` in main process response headers (CWE-1021) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-042` | Incorrect native buffer size for marshaling fixed structs (CWE-131) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-043` | Off-by-one allocation for UTF-16 interop strings (CWE-131) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-044` | `StructureToPtr` writes larger structure into undersized unmanaged buffer (CWE-131) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-045` | `Marshal.Copy` length driven by untrusted value without bounds check (CWE-131) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-046` | Detailed debug message disclosure in production logs/UI (CWE-1295) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-047` | Electron main process logs verbose Chromium crash/debug details in production (CWE-1295) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-048` | Electron `webContents` permission handler allows all requests | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-049` | Unsafe `shell.openExternal` with unvalidated URL schemes | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-050` | Disabled Electron process sandbox in production window config | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-051` | Broad IPC surface: generic channels without argument schema validation | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-052` | Unverified auto-update feed/signature in desktop updater | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-053` | VSTO macro/addin trust decision based on mutable document metadata | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-054` | `[DllImport]` без абсолютного пути к нативной DLL — риск DLL search order hijacking (CW... | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-055` | Логирование полного пути `Environment.GetFolderPath` без маскировки — утечка профиля по... | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-056` | `LoadLibrary` из пользовательского/Temp пути без проверки подписи (CWE-427) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-057` | `Assembly.LoadFile` из Downloads без верификации (CWE-427) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-058` | WPF `TextBlock` с полным системным путём пользователя (CWE-497) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-059` | WinForms `MessageBox` с полным путём профиля (CWE-497) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-060` | `OpenFileDialog` результат в заголовке окна без маскировки (CWE-497) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-061` | `DllImport` с поиском в `%TEMP%` (CWE-427) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-062` | Отображение `Assembly.Location` пользователю в UI (CWE-497) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-063` | Electron `dialog.showOpenDialog` path в `document.title` (CWE-497) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-064` | NativeLibrary.Load из relative path в add-in (CWE-427) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-065` | `ToolStripStatusLabel` с полным путём к roaming app data (CWE-497) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-066` | TOCTOU: `File.Exists` затем `File.OpenRead` без атомарной блокировки (CWE-367) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-067` | `DllImport` без абсолютного пути к нативной DLL в каталоге аддина (CWE-427) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-068` | Небезопасный `File.Open` без `FileShare`/`FileOptions` при конкурирующей записи (CWE-367) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-069` | Неверный размер буфера `stackalloc` для interop (CWE-131) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-070` | VSTO: логирование полного набора переменных окружения (CWE-497) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-071` | VSTO: вывод `Environment.GetCommandLineArgs()` в telemetry (CWE-497) | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `INS-072` | Insight: xlsx (SheetJS 0.18.5) cell from user written without formula neutralization | Prefix formula-meta chars in .xlsx exports; central `sanitizeForExcelCell()` for all user/DB fields. |
| `INS-073` | Insight: `XLSX.utils.json_to_sheet` from untrusted rows без санитизации | Map all values through sanitize before `json_to_sheet` / `aoa_to_sheet`. |
| `INS-074` | Insight: `xlsx.writeFile` экспорт без нейтрализации формул в колонках | Never write raw user strings to xlsx cells; apply CSV/Excel injection defenses. |
| `INS-075` | Insight: `xlsx` read → re-export цепочка без ре-sanitization | On re-export pipeline, treat every cell as untrusted input. |
| `INS-076` | Insight: mammoth `convertToHtml` без ограничения размера входного DOCX | Enforce max doc size before mammoth; reject oversized ZIP/docx. |
| `INS-077` | Insight: mammoth извлечение без hardening XML внутри DOCX (внешние сущности) | Pre-validate docx zip and XML parts; disable entity expansion in XML pipeline. |
| `INS-078` | Insight: `docx` npm / PizZip открытие без проверки compression ratio (zip bomb) | Enforce max uncompressed size and compression ratio for OOXML containers. |
| `INS-079` | Insight: `JSZip` загрузка `.docx/.pptx` без лимита распакованного объёма | Track cumulative uncompressed bytes; abort on threshold (zip bomb). |
| `INS-080` | Insight: `pdfjs-dist` `getDocument` без лимита на размер/страницы | Cap PDF bytes and pages; stream with limits. |
| `INS-081` | Insight: `pdfjs-dist` workerSrc с недоверенного origin | Host pdf.worker.js from same origin; integrity attribute. |
| `INS-082` | Insight: `word-extractor` без таймаута и лимита памяти | Timeout + size limit around word-extractor; reject huge binaries. |
| `INS-083` | Insight: `docx` XML part `word/document.xml` парсится с `xml2js` `mergeAttrs` без отклю... | Parse OOXML with XXE-safe XML settings; no external entities. |
| `INS-084` | Insight: ExcelJS `worksheet.addRow` с пользовательскими строками в отчёт | Sanitize ExcelJS rows before commit; same rules as SheetJS. |
| `INS-085` | Insight: `mammoth` `convertToHtml` + встроенные `styleMap` из пользователя | Do not pass user-controlled styleMap to mammoth; allowlist only. |
| `INS-086` | Insight: распаковка `.pptx` для превью без ratio check | Same zip-bomb defenses as docx for pptx OOXML. |
| `INS-087` | Insight: `fflate` unzip `xlsx` array без лимита | Limit entries and total bytes when using fflate/unzip on xlsx. |
| `INS-088` | Insight: `pdfjs` `getMetadata` доверие к `/Title` для XSS в UI | Treat PDF metadata as untrusted; never HTML-embed without encode. |
| `INS-089` | Insight: mammoth `embedImage` с пользовательским base64 | Strict allowlist for embedded image resolution in mammoth. |
| `INS-090` | Insight: CSV → xlsx pipeline без нейтрализации (формула в CSV) | Apply CSV injection rules before promoting to xlsx. |
| `INS-091` | Insight: `word-extractor` + последующая запись в HTML без escape | Never assign extracted text to innerHTML without sanitization. |
| `INS-092` | OpenAI SDK: `chat.completions.create` без схемы ответа для JSON-логики | Use `json_schema` response_format or validate with Zod before branching logic. |
| `INS-093` | OpenAI: доверие к `role`/`tool_calls` без проверки | Never branch security on model-supplied role strings; server-side allowlist. |
| `INS-094` | OpenAI: `completion.choices[0].message.content` как команда без allowlist | Validate structured output; reject unknown fields; no shell exec from model text. |
| `INS-095` | OpenAI: streaming chunks собраны в объект без финальной Zod-проверки | Finalize streamed LLM output with schema validation. |
| `INS-096` | OpenAI: `tools`/`function` arguments без типизации | Per-tool Zod schema for JSON arguments from OpenAI. |
| `INS-097` | OpenAI: `system` + `developer` messages логируются через `electron-log` | Redact system/developer prompts from electron-log; structured logging without secrets. |
| `INS-098` | OpenAI: system prompt в `console.log` / renderer DevTools | Ban console logging of system prompts outside sealed dev diagnostics. |
| `INS-099` | OpenAI: ответ модели напрямую в `ipcRenderer.send` без валидации | Validate OpenAI payloads before IPC; duplicate validation in main. |
| `INS-100` | Electron 36: `BrowserWindow` без явного `nodeIntegration: false` | Always set `nodeIntegration: false` and `contextIsolation: true` explicitly in main. |
| `INS-101` | Electron: `webPreferences` без `contextIsolation: true` | Explicit `contextIsolation: true` for every BrowserWindow. |
| `INS-102` | Electron: `ipcMain.handle` без проверки `event.senderFrame` | Validate `event.senderFrame` / sender URL before handling IPC. |
| `INS-103` | Electron: `ipcMain.handle` доверяет `event.sender` без `frame` | Pair IPC handlers with sender frame / origin checks. |
| `INS-104` | Electron: удалённый `preload` path из конфига пользователя | Never load preload from user-controlled paths; allowlist under app package. |
| `INS-105` | Electron: `webPreferences.webSecurity: false` | Keep `webSecurity: true` except rare dev-only exceptions. |
| `INS-106` | Electron: `ipcMain.handle` + `shell.openExternal` с аргументом от renderer | Validate URLs before `openExternal` from IPC payloads. |
| `INS-107` | Electron: merge `defaultWebPreferences` из `userData` JSON | Immutable hardened webPreferences; ignore user overrides for security keys. |
| `INS-108` | Electron: `session.setPermissionRequestHandler` всегда `cb(true)` | Default deny; explicit allowlist for media/geolocation. |
| `INS-109` | Electron: `protocol.registerFileProtocol` без path traversal check | Validate file paths in custom protocols; prevent traversal. |
| `INS-110` | Electron: `desktopCapturer` + AI без user consent | Gate screen capture behind explicit user consent. |
| `INS-111` | Insight: `xlsx` `sheet_to_csv` затем email без escape | Sanitize CSV exports from xlsx before messaging. |
| `INS-112` | Insight: `mammoth` `convertToHtml` + `innerHTML` в Electron | Sanitize mammoth HTML before DOM insertion. |
| `INS-113` | Insight: `pdfjs` page text → SQL без параметризации | Parameterize DB; treat PDF text as untrusted. |
| `INS-114` | Insight: `docx` template engine `{{user}}` без escape | Escape template fields for docx generation. |
| `INS-115` | Insight: OpenAI `responses.parse` / structured output без `strict: true` | Use strict JSON schema where API allows. |
| `INS-116` | OpenAI: логирование полного `messages` в `pino`/`winston` | Redact OpenAI message bodies in logs. |
| `INS-117` | Electron: `contextBridge.exposeInMainWorld` с функцией без аргументов проверки | Validate IPC args in preload bridge and main. |
| `INS-118` | Electron: `ipcMain.on` (legacy) вместо `handle` без проверки sender | Prefer `handle` with sender validation over legacy `on`. |
| `INS-119` | Insight: `pdfjs` `getDocument` data URL с user data | Block unbounded base64 PDF from user input. |
| `INS-120` | Insight: `word-extractor` на UNC path без доверия | Restrict UNC/network paths for extraction. |
| `INS-121` | Insight: xlsx `cellStyles` из пользователя | Do not apply user-controlled styles that embed formulas. |
| `INS-122` | Insight: mammoth `convertToMarkdown` → markdown XSS | Sanitize markdown output from mammoth. |
| `INS-123` | Insight: `docx` hyperlink из пользователя | Validate hyperlinks in generated docx. |
| `INS-124` | OpenAI: `parallel_tool_calls` без лимита веток | Limit parallel tool execution from model. |
| `INS-125` | OpenAI: кэш ответа LLM на диск без шифрования | Encrypt cached LLM responses; no plaintext PII. |
| `INS-126` | Electron: `nativeImage` из пользовательского пути без проверки | Validate paths for nativeImage loads. |
| `INS-127` | Electron: `Menu` item `click` с `remote` shell | Validate URLs in menu handlers. |
| `INS-128` | Insight: `xlsx` shared strings table pollution | Sanitize shared strings when merging workbooks. |
| `INS-129` | Insight: `pptxgenjs` text from user без sanitize | Sanitize user text in pptxgenjs slides. |
| `INS-130` | Insight: `pdf-lib` embed font from user path | Restrict embedded fonts to trusted sources. |
| `INS-131` | OpenAI: `temperature`/`top_p` max для production | Bound sampling params for production AI paths. |
| `INS-132` | OpenAI: отсутствие `seed` для воспроизводимости аудита | Use seed for reproducibility when policy requires. |
| `INS-133` | Electron: `powerMonitor` + IPC без auth | Gate system events on IPC. |
| `INS-134` | Electron: `clipboard` write из renderer без проверки | Mediate clipboard IPC in main. |
| `INS-135` | Insight: `mammoth` + `cheerio` load без sanitize | Sanitize cheerio HTML from mammoth. |
| `INS-136` | Insight: `xlsx` password-protected workbook без rate limit | Rate-limit xlsx password attempts. |
| `INS-137` | Insight: `pdfjs` `getOperatorList` утечка в лог | Do not log PDF operator lists in production. |
| `INS-138` | OpenAI: `metadata` поля с PII в `store` | Minimize OpenAI request metadata. |
| `INS-139` | Electron: `globalShortcut` регистрация без проверки фокуса | Validate focus before global shortcuts. |
| `INS-140` | Electron: `dialog.showSaveDialog` path в `openExternal` | Validate save dialog paths before opening. |
| `INS-141` | Insight: `xlsx` CSV delimiter injection | Handle CSV delimiter injection in xlsx roundtrip. |
| `INS-142` | Insight: `docx` `header`/`footer` user HTML | Safe XML/HTML for headers/footers. |
| `INS-143` | Insight: `pdfjs` `getAnnotations` исполнение | Treat PDF annotations as untrusted. |
| `INS-144` | OpenAI: `response_format` JSON + `tools` одновременно без тестов | Test tools + JSON schema together. |
| `INS-145` | Electron: `BrowserView` без `webPreferences` копии | Set full webPreferences on BrowserView. |
| `INS-146` | Electron: `utilityProcess` fork без argv allowlist | Validate utility process arguments. |
| `INS-147` | Insight: `mammoth` `ignoreEmptyParagraphs: false` + huge doc | Combine mammoth options with size caps. |
| `INS-148` | Insight: `xlsx` `sheet_to_json` `defval` user injection | Do not use user input as defval in sheet_to_json. |
| `INS-149` | OpenAI: `max_tokens` не ограничен для UI path | Bound max_tokens for interactive flows. |
| `INS-150` | Electron: `safeStorage` key fallback | No plaintext fallback when safeStorage unavailable. |
| `INS-151` | Insight: Infinity release checklist — отсутствие `npm audit` в CI для Insight deps | Run npm audit in CI for Insight stack. |
| `INS-152` | Insight: `electron` `remote` module (deprecated) | Ban `@electron/remote`; use contextBridge. |

## Verification

**Verification:** Check the gold testbed file(s) below for `Vulnerable: <ID>` markers (static Semgrep + `detection-matrix.md` ground truth).

- [`gold-standard-testbed/insight_vulnerable.ts`](../gold-standard-testbed/insight_vulnerable.ts)
- [`gold-standard-testbed/insight_vulnerable.cs`](../gold-standard-testbed/insight_vulnerable.cs)

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

