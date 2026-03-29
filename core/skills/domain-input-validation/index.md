# Domain Input Validation

## Stack overview

Canonical validation controls for untrusted input: traversal, SSRF, code/command injection, and unsafe parsing.

## Top threats

- **Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists.**: 75 metrics (`PY-007`, `PY-012`, `PY-014`, `PY-015`)
- **Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering.**: 66 metrics (`NJS-001`, `NJS-002`, `NJS-007`, `NJS-003`)
- **Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input.**: 4 metrics (`CWE-601-CSH-PROCESS-START-URL`, `CWE-81-CSH-WEBBROWSER-XSS`, `CWE-1321-CSH-DYNAMIC-EXPANDO`, `CWE-749-CSH-COMVISIBLE-DANGEROUS`)
- **CWE Final Certification**: 3 metrics (`CWE-79-PY-DJANGO-SAFE`, `CWE-89-PG-COPY-PROGRAM`, `CWE-89-PLPGSQL-EXECUTE`)
- **Атомарные temp API; для concurrent writes — file locks; валидировать path после `mkstemp`.**: 1 metrics (`CWE-123-PY-TEMPFILE-TOCTOU`)
- **Выполнять нормализацию до фиксированной точки (loop until stable), затем строгую canonicalization-проверку и allowlist-валидацию итогового значения.**: 1 metrics (`CWE-85-174-UNIVERSAL-ONCE`)
- **Для динамических ответов всегда добавлять `X-Content-Type-Options: nosniff` и корректный `Content-Type`, исключая MIME sniffing.**: 1 metrics (`CWE-80-UNIVERSAL-NOSNIFF`)
- **Исключить динамическое исполнение строкового JS из недоверенных данных; передавать данные через безопасный IPC API с валидацией схемы.**: 1 metrics (`DSK-100`)
- **Нормализовать/валидировать тип параметров (single-value), отклонять массивы/дубликаты в критичных auth/ACL полях.**: 1 metrics (`CWE-20-HPP`)
- **Перед системными вызовами удалять/блокировать `\\x00` и управляющие символы, нормализовать input и применять allowlist форматов аргументов.**: 1 metrics (`CWE-20-UNIVERSAL-NULLBYTE`)
- **Проверять `start/end` против `buffer.byteLength`; отклонять отрицательные/NaN индексы; использовать typed array helpers с валидацией.**: 1 metrics (`CWE-124-JS-ARRAYBUFFER-SLICE`)
- **Строить XML через безопасные builder API и обязательно экранировать спецсимволы (`<`, `>`, `&`, `'`, `"`).**: 1 metrics (`CWE-91-UNIVERSAL-XML-CONCAT`)

## Pattern catalog

Complete Anti-Pattern / Safe-Pattern definitions live in [`patterns.md`](patterns.md). The table below is a **table of contents** by metric ID.

| ID | Metric | Stack |
|---|---|---|
| `PY-007` | SSRF via user URL fetch | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PY-012` | SQL injection in dynamic execute | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PY-014` | Path traversal in file operations | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PY-015` | eval/exec on untrusted data | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PY-021` | SQLAlchemy text injection | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PY-025` | Missing webhook signature check | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PY-110` | Media path traversal | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `NJS-001` | Command injection in exec | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-002` | Path traversal in fs access | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-007` | SSRF in fetch | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `PY-001` | FastAPI debug enabled in production | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PY-003` | Unsafe pickle deserialization | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PY-004` | Subprocess shell injection | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PY-005` | YAML unsafe loader | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PY-006` | Weak temp file handling | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PY-008` | Missing request timeout in outgoing calls | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PY-013` | ORM mass assignment | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PY-016` | Insecure CORS wildcard with credentials | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PY-018` | Async endpoint with blocking I/O | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PY-019` | Playwright launch with insecure flags | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PY-020` | FastAPI route without response_model returning DB object | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PY-022` | Pydantic construct bypass for external input | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PY-029` | Celery task deserialization risk | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `PY-030` | Unvalidated redirect target | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `DJA-001` | CSRF Disabled: view без CSRF-защиты | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `DJA-002` | Raw SQL Injection: строковая конкатенация в SQL | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `DJA-003` | DEBUG=True in Production | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `DJA-004` | Mass Assignment: `ModelForm` без явных `fields` | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `DJA-005` | Insecure ALLOWED_HOSTS wildcard | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `DJA-006` | Open Redirect через `next` без проверки | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `DJA-009` | Unsafe file upload path (path traversal) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `DJA-011` | XSS via `mark_safe`: доверие пользовательскому HTML | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `DJA-013` | Insecure `.extra()` where clause | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `DJA-016` | ReDoS in URL patterns via complex `re_path` | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `DJA-017` | ModelForm `exclude=[]` abuse | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `DSK-100` | Remote Code Injection via executeJavaScript | Исключить динамическое исполнение строкового JS из недоверенных данных; передавать данные через безопасный IPC API с валидацией схемы. |
| `NJS-003` | Event Loop Blocking через `*Sync` API в request handlers | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-004` | Insecure Serialization / unsafe eval processing | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-006` | Open Redirect via untrusted URL forwarding | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-008` | Broken CORS policy with wildcard + credentials | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-011` | Server-Side Prototype Pollution in merge/parsing flows | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-012` | Unsafe Buffer allocation | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-013` | HTTP Parameter Pollution without type guards | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-014` | Insecure Sandbox with `vm` module execution | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-015` | Event Loop ReDoS in server validators/routes | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-017` | Dependency Confusion & Integrity gaps in package sources | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-018` | Insecure Header Leakage: X-Powered-By exposed | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-020` | Unsafe File Deletion/Cleanup with user-controlled paths | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-022` | Weak password hashing parameters | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-023` | NoSQL Injection in Mongo-style filters | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-025` | Open CORS preflight methods/headers overexposure | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-026` | Mass Assignment через прямую передачу `req.body` в ORM | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-027` | Safe Buffer Creation: `Buffer.from(variable)` без type guard | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-028` | SCA / Audit Gate отсутствует в npm scripts | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-029` | SSTI / Unsafe template raw output tags | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-031` | Prototype Pollution через spread operator из user input | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NJS-035` | Sensitive data retained in long-lived heap strings | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `FTS-001` | XSS Prevention: unsafe HTML rendering without sanitization | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `FTS-004` | Insecure Communication: postMessage without origin validation | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `FTS-006` | Missing CSP Hardening for script execution | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `FTS-007` | Clickjacking Protection Missing | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `FTS-010` | Service Worker Cache Poisoning Risk | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `FTS-011` | Unsafe Execution: dynamic code execution from strings | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `FTS-012` | Prototype Pollution: unsafe deep merge without key guards | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `FTS-013` | Global Namespace Pollution and native prototype extension | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `FTS-015` | RegExp DoS / ReDoS with catastrophic backtracking | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `FTS-016` | Sequential Await DoS in loops for external calls | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-78-PY` | CWE-78 OS Command Injection (Python dangerous process APIs) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-89-PY` | CWE-89 SQL Injection (Python raw execute string formatting) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-94-PY` | CWE-94 Code Injection (Python dynamic execution) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-78-JS` | CWE-78 OS Command Injection (Node.js command execution) | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-79-JS` | CWE-79 XSS (unsafe HTML rendering in React/Vue) | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-94-JS` | CWE-94 Code Injection (JavaScript dynamic execution) | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-22-PY` | Path Traversal in Python file path join | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-434-PY` | Unsafe File Upload with original filename | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-22-JS` | Path Traversal in Node IPC file operations | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-614-JS` | Insecure Cookie flags in web builds | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-611-PY` | XXE in XML parsing (Python lxml) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-502-PY` | Insecure deserialization in Python | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-1321-JS` | Prototype Pollution via unsafe object merge | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-502-JS` | Insecure deserialization in Node.js libs | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-918-PY` | SSRF in Python HTTP client calls with untrusted URL | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-918-JS` | SSRF in JS/Node HTTP calls with untrusted URL | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-1333-JS` | ReDoS via dynamic RegExp from user input | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-601-PY` | Open Redirect in Python without allowlist validation | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-601-JS` | Open Redirect in Express/Fastify without host/protocol checks | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-91-PY` | XML Injection via unsanitized user fragments in XML templates | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-918-PY-PROTO` | SSRF with missing protocol allowlist in Python | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-918-JS-PROTO` | SSRF with missing protocol validation in JS/Node | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-91-PY-IDENTITY` | Incorrect identity comparison (`is`) for strings/numbers in Python validation/auth logic | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-1025-JS` | Loose equality (`==`) in token/authorization checks | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-89-PY-DJA-RAW` | Django SQL Injection via `.extra(where=...)` / `.raw()` with string concatenation | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-89-JS-ORM-RAW` | SQL Injection in Sequelize/Knex raw query APIs with interpolation | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-20-UNIVERSAL-NULLBYTE` | Missing null-byte/control-char sanitization in inputs sent to system calls | Перед системными вызовами удалять/блокировать `\\x00` и управляющие символы, нормализовать input и применять allowlist форматов аргументов. |
| `CWE-20-HPP` | HTTP Parameter Pollution in security-critical parameter parsing | Нормализовать/валидировать тип параметров (single-value), отклонять массивы/дубликаты в критичных auth/ACL полях. |
| `CWE-611-PY-MINIDOM` | XML parser DoS risk with `xml.dom.minidom.parse()` on untrusted XML | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-611-PY-ELEMENTTREE` | XML parser DoS risk with `xml.etree.ElementTree.parse()` (billion laughs) | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-611-JS-LIBXMLJS-NOENT` | XXE/entity expansion risk in `libxmljs.parseXml(..., { noent: true })` | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-91-UNIVERSAL-XML-CONCAT` | XML Injection via string concatenation with user-controlled fragments | Строить XML через безопасные builder API и обязательно экранировать спецсимволы (`<`, `>`, `&`, `'`, `"`). |
| `CWE-85-174-UNIVERSAL-ONCE` | Single-pass normalization bypass via one-time `replace()` / `re.sub()` filtering | Выполнять нормализацию до фиксированной точки (loop until stable), затем строгую canonicalization-проверку и allowlist-валидацию итогового значения. |
| `CWE-85-JS-SLASH-FILTER` | Incomplete slash filtering in Node.js checks (`/` only, ignores `//`) | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-79-PY-DJANGO-SAFE` | XSS via Django ` | CWE Final Certification |
| `CWE-79-PY-DJANGO-AUTOESCAPE-OFF` | XSS via `{% autoescape off %}` around untrusted variables | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-79-PY-HTMLRESPONSE` | XSS in FastAPI/Flask HTML responses built via f-strings/concatenation | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-79-JS-SSR-RAW` | Unescaped SSR template output (`<%-` in EJS / `{{{` in Handlebars) | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-80-UNIVERSAL-NOSNIFF` | Missing `X-Content-Type-Options: nosniff` with dynamic content responses | Для динамических ответов всегда добавлять `X-Content-Type-Options: nosniff` и корректный `Content-Type`, исключая MIME sniffing. |
| `CWE-1336-PY-JINJA2-RTS` | SSTI risk: Jinja2 template created directly from user input | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-1336-PY-MAKO-RTS` | SSTI risk: Mako Template from user-controlled source | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-1336-JS-PUG-EJS-RTS` | SSTI risk in Node.js when compiling/rendering user template source | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-1336-JS-LODASH-TEMPLATE` | Code/template injection via `_.template(userInput)` | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-943-PY-MONGO-DICT` | NoSQL Injection: passing raw `request.json` dict into PyMongo/MongoEngine queries | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-943-PY-DJANGO-KWARGS` | Unsafe `**kwargs` unpacking from user input in Django ORM filters | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-943-JS-MONGO-FILTER` | NoSQL Injection in Node.js by using `req.body/req.query` as Mongo filter | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-943-JS-SEQUELIZE-WHERE` | Unsafe Sequelize `where` from full `req.query` object | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-23-PY-TEMPLATE-FILE` | Path Traversal via user-controlled template/file path in Django/Flask | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-23-JS-EXPRESS-SENDFILE` | Path Traversal in Express `res.sendFile`/`res.render` with `req.params/query` | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-23-JS-DYNAMIC-REQUIRE` | Dynamic `require()`/`import()` path from request data | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-89-PY-SQLALCHEMY-TEXT` | SQL Injection in SQLAlchemy `text()` with user concatenation | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-89-PY-SQLALCHEMY-ORDERBY` | Unsafe dynamic `order_by(user_input)` without allowlist mapping | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-89-JS-ORM-QUERYRAW` | SQL Injection via TypeORM/Sequelize raw query builders with concatenation | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-89-PG-COPY-PROGRAM` | PostgreSQL command/file injection via `COPY ... FROM PROGRAM` or `lo_import()` with use... | CWE Final Certification |
| `CWE-89-PLPGSQL-EXECUTE` | SQL Injection in PL/pgSQL dynamic `EXECUTE` without proper quoting | CWE Final Certification |
| `CWE-943-REDIS-CMD` | Redis command injection via dynamic `execute_command` / `send_command` arguments | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-943-REDIS-LUA-EVAL` | Redis Lua injection via `eval()`/`evalsha()` script body concatenation | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-89-PY-SQLALCHEMY-ASYNC-TEXT` | SQL Injection in SQLAlchemy Async via `await session.execute(text(...))` concatenation | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-943-REDIS-RQ-IREDIS-CMD` | Redis command injection in RQ/ioredis command APIs | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-943-REDIS-RQ-IREDIS-EVAL` | Lua script injection in Redis `eval()` from user-concatenated script body | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-918-NEXTJS-AXIOS-SSRF` | SSRF in Next.js (`getServerSideProps`/API routes) via `axios.get/post(userInput)` witho... | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-346-AXIOS-WITHCREDENTIALS` | Insecure global `axios.defaults.withCredentials = true` without trusted `baseURL` restr... | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-79-REACT-DANGEROUSLYSETHTML` | React XSS via `dangerouslySetInnerHTML` without `DOMPurify.sanitize()` wrapper | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-1321-TS-DEEPMERGE` | Prototype pollution risk in recursive deep merge without `__proto__/constructor` key gu... | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-94-OPENROUTER-PROMPT-CONCAT` | Prompt injection risk: user input concatenated into LLM provider `messages` without ... | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-116-LLM-HTML-UNTRUSTED` | Untrusted LLM output (speech/transcription + chat APIs) rendered as HTML without sanitization | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-915-NODE-ASSIGN-MERGE` | Prototype pollution via `Object.assign()` / `_.merge()` with untrusted `req.body` object | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-915-SQLMODEL-MASS-ASSIGN` | SQLModel mass assignment via `model_validate()`/`from_orm()`/`**request.json` without `... | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-89-SQLMODEL-TEXT-FSTRING` | SQL injection in SQLModel query with `select().where(text(f"...{var}"))` | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-601-CSH-PROCESS-START-URL` | Open redirect / unsafe URL launch via `Process.Start(url)` from untrusted input | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CWE-81-CSH-WEBBROWSER-XSS` | XSS risk in desktop WebView/WebBrowser via unescaped `DocumentText` / `InvokeScript` input | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CWE-1321-CSH-DYNAMIC-EXPANDO` | Mapping JSON into `dynamic`/`ExpandoObject` without strict schema validation | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CWE-749-CSH-COMVISIBLE-DANGEROUS` | `[ComVisible(true)]` class exposes public methods executing sensitive operations (`File... | Use using/try-finally and safe .NET APIs; enforce strict allowlists for untrusted input. |
| `CWE-123-PY-TEMPFILE-TOCTOU` | TOCTOU: проверка `os.path.exists` перед `open` без атомарного создания | Атомарные temp API; для concurrent writes — file locks; валидировать path после `mkstemp`. |
| `CWE-124-JS-ARRAYBUFFER-SLICE` | Небезопасное копирование из `ArrayBuffer` без проверки границ среза | Проверять `start/end` против `buffer.byteLength`; отклонять отрицательные/NaN индексы; использовать typed array helpers с валидацией. |
| `CWE-20-PY-VAL-EXTRA-01` | Невалидированный `float()` из query для критичного лимита | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-20-PY-VAL-EXTRA-02` | Пустая строка как путь к файлу после `strip()` | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-20-JS-VAL-EXTRA-01` | `parseInt` без radix на пользовательском вводе | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-20-JS-VAL-EXTRA-02` | Доверие `JSON.parse` без try/catch на внешнем теле | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-89-PY-VAL-EXTRA-01` | Конкатенация в `ORDER BY` с «белым списком» только в комментарии | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-79-JS-VAL-EXTRA-01` | `href` из API без протокольной проверки | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `CWE-918-PY-VAL-EXTRA-01` | `ipaddress.ip_address` на пользовательском хосте без blocklist | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-502-PY-VAL-EXTRA-01` | `yaml.load` на конфиге из upload | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-611-PY-VAL-EXTRA-01` | `lxml.etree.fromstring` с `resolve_entities` по умолчанию на внешнем XML | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-20-PY-VAL-EXTRA-03` | Непроверенный `int()` из multipart filename | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-1268-PY-IPC-CHANNEL` | Подмена IPC/сокетного канала без проверки peer identity | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-1271-PY-SIGNED-ERR` | Игнорирование ошибки проверки подписи в цепочке обновлений | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-1280-PY-MARK-CRITICAL` | Критичный код помечен как «optional» в политике | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |
| `CWE-1285-PY-NEGOTIATION` | Небезопасный downgrade при согласовании протокола | Use strict Pydantic BaseModel schemas for input/output, including response_model and field allowlists. |

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

