# Java / Spring

## Stack overview

Server-side **Java** with **Spring**-style patterns: injection, deserialization, JWT, multipart, and path handling. Metrics are prefixed **`JAVA`**.

## Top threats

- Code/exec and SpEL/Jackson risks (`JAVA-001`–`JAVA-011`).
- XXE and Spring Security misconfig (`JAVA-012`–`JAVA-014`).
- Open redirect, JWT checks, crypto (`JAVA-015`–`JAVA-020`).

## Pattern catalog

Complete Anti-Pattern / Safe-Pattern definitions live in [`patterns.md`](patterns.md). The table below is a **table of contents** by metric ID.

| ID | Metric | Stack |
|---|---|---|
| `JAVA-001` | Java Eval Injection: выполнение выражения из пользовательского ввода | `String expr = request.getParameter("expr");` `if (!expr.matches("^[0-9+\\-*/(). ]{1,64}$")) throw new IllegalArgumentException();` `...` `Object result = safeMathEval(expr);` |
| `JAVA-002` | Runtime Exec Injection: `Runtime.getRuntime().exec` со строкой команды | `String host = req.getParameter("host");` `if (!host.matches("^[a-zA-Z0-9.-]{1,255}$")) throw new IllegalArgumentException();` `...` `new ProcessBuilder("ping","-c","1",host).start();` |
| `JAVA-003` | ProcessBuilder Command Injection: shell-строка через `/bin/sh -c` | `String action = req.getParameter("action");` `Map<String,List<String>> allowed = Map.of("uptime", List.of("uptime"));` `...` `new ProcessBuilder(allowed.get(action)).start();` |
| `JAVA-004` | Unsafe Reflection: загрузка класса из пользовательского ввода | `String key = req.getParameter("handler");` `Map<String,Class<?>> allow = Map.of("health", HealthHandler.class);` `...` `Class<?> c = allow.get(key);` |
| `JAVA-005` | Method Invocation Injection: вызов произвольного метода через reflection | `String method = req.getParameter("method");` `Set<String> allow = Set.of("health","status");` `if (!allow.contains(method)) throw new SecurityException();` `...` `target.getClass().getMethod(method).invoke(target);` |
| `JAVA-006` | JDBC Command Composition: SQL/command фрагмент из input без allowlist | `String order = req.getParameter("order");` `if (!Set.of("name","created_at").contains(order)) order = "name";` `...` `String q = "SELECT * FROM users ORDER BY " + order;` |
| `JAVA-007` | SpEL Injection: expression parser на пользовательских данных | `String key = req.getParameter("key");` `Map<String,String> allow = Map.of("env","prod");` `...` `return allow.getOrDefault(key, "n/a");` |
| `JAVA-008` | Nashorn/Graal JS Injection: выполнение произвольного JS кода | `String cmd = req.getParameter("cmd");` `if (!Set.of("normalize").contains(cmd)) throw new SecurityException();` `...` `runFixedJsFunction(cmd);` |
| `JAVA-009` | SpEL Injection (Spring): expression из запроса исполняется в контексте | `String key = request.getParameter("key");` `Map<String,Object> allowed = Map.of("health", true);` `...` `return allowed.getOrDefault(key, false);` |
| `JAVA-010` | Jackson Unsafe Deserialization: default typing на недоверенных данных | `ObjectMapper mapper = new ObjectMapper();` `...` `mapper.disableDefaultTyping();` `UserDTO obj = mapper.readValue(body, UserDTO.class);` |
| `JAVA-011` | Log4j/JNDI Deserialization Risk: логирование сырых user-строк | `String msg = request.getParameter("msg");` `String safe = msg.replace("${", "\\${");` `...` `logger.error("msg={}", safe);` |
| `JAVA-012` | XXE in XML Parsers: внешние сущности не запрещены | `DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();` `f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);` `f.setFeature("http://xml.org/sax/features/external-general-entities", false);` `f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);` |
| `JAVA-013` | Insecure Spring Security: `permitAll()` на критичных эндпоинтах | `http.authorizeHttpRequests(auth -> auth` `    .requestMatchers("/admin/**").hasRole("ADMIN")` `);` |
| `JAVA-014` | CSRF Disabled Globally в stateful приложении | `http.csrf(csrf -> csrf` `    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())` `);` |
| `JAVA-015` | Open Redirect in Spring MVC | `String next = request.getParameter("next");` `if (!next.startsWith("/")) next = "/";` `...` `return "redirect:" + next;` |
| `JAVA-016` | JWT Signature Bypass: no alg check in parser | `JwsHeader<?> h = Jwts.parserBuilder().build().parseClaimsJws(token).getHeader();` `if (!"HS256".equals(h.getAlgorithm())) throw new SecurityException();` `Claims c = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();` |
| `JAVA-017` | Insecure Random for tokens (`java.util.Random`) | `SecureRandom r = new SecureRandom();` `...` `byte[] token = new byte[32];` `r.nextBytes(token);` |
| `JAVA-018` | Hardcoded Secrets in config/code | `String jwtSecret = System.getenv("JWT_SECRET");` `if (jwtSecret == null) throw new IllegalStateException();` |
| `JAVA-019` | Unbounded Multipart Upload (DoS risk) | `if (file.getSize() > 5 * 1024 * 1024) throw new IllegalArgumentException();` `...` `byte[] data = file.getBytes();` |
| `JAVA-020` | Path Traversal in file download | `String p = request.getParameter("path");` `Path target = Paths.get(root, p).normalize();` `if (!target.startsWith(Paths.get(root))) throw new SecurityException();` |

## Verification

**Verification:** Check the gold testbed file(s) below for `Vulnerable: <ID>` markers (static Semgrep + `detection-matrix.md` ground truth).

- [`gold-standard-testbed/multi_lang_vulnerable/java_vulnerable.java`](../gold-standard-testbed/multi_lang_vulnerable/java_vulnerable.java)

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

