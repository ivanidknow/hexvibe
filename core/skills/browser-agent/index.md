# Browser Agent (Playwright / automation)

## Stack overview

**Playwright**-driven automation in Python and JavaScript: sandbox, navigation, downloads, and script execution boundaries. Metrics are prefixed **`BRW`**.

## Top threats

- Unsafe Chromium flags and TLS downgrades (`BRW-001`–`BRW-003`, `BRW-006`).
- SSRF and local metadata access via `goto` (`BRW-007`, `BRW-008`).
- XSS / JS injection / prototype pollution in bridged code (`BRW-011`–`BRW-013`).

## Pattern catalog

Complete Anti-Pattern / Safe-Pattern definitions live in [`patterns.md`](patterns.md). The table below is a **table of contents** by metric ID.

| ID | Metric | Stack |
|---|---|---|
| `BRW-001` | Playwright: запуск без sandbox (`--no-sandbox`) | `browser = await p.chromium.launch(` `  args=[],` `  headless=True,` `)` |
| `BRW-002` | Playwright: `ignoreHTTPSErrors=True` | `context = await browser.new_context(ignoreHTTPSErrors=False)` `page = await context.new_page()` |
| `BRW-003` | Prod: `headless: false` | `browser = await p.chromium.launch(headless=True)` |
| `BRW-004` | WebRTC metadata leakage через page.evaluate() | `await page.route(\"**/*\", lambda route: route.abort() if \"stun\" in route.request.url else route.continue_())` |
| `BRW-005` | Пользовательский JS через page.evaluate() | `allowed = {\"scrollToTop\",\"extractText\"}` `cmd = request.json()[\"cmd\"]` `if cmd not in allowed: raise ValueError(\"cmd rejected\")` `await page.evaluate(\"(arg) => window.scrollTo(0,0)\", None)` |
| `BRW-006` | Отключение защитных флагов Chromium | `browser = await p.chromium.launch(args=[])` |
| `BRW-007` | File Protocol Restriction: `file://` разрешен в `page.goto()` | `target = user_input_url` `if target.startswith(\"file://\"):` `    raise ValueError(\"file protocol is forbidden\")` `await page.goto(target, wait_until=\"domcontentloaded\")` |
| `BRW-008` | SSRF via Browser: доступ к localhost/metadata endpoints | `import ipaddress` `from urllib.parse import urlparse`  `def _blocked_host(host: str) -> bool:` `    if host in {\"localhost\"}:` `        return True` `    try:` `        ip = ipaddress.ip_address(host)` `        return ip.is_loopback or ip.is_private or ip.is_link_local` `    except ValueError:` `        return False`  `parsed = urlparse(url)` `if _blocked_host(parsed.hostname or \"\") or (parsed.hostname == \"169.254.169.254\"):` `    raise ValueError(\"blocked destination\")` `await page.goto(url, wait_until=\"domcontentloaded\")` |
| `BRW-009` | Zombies & Leaks: контекст не закрывается, timeout не задан | `context = await browser.new_context()` `try:` `    page = await context.new_page()` `    page.set_default_navigation_timeout(10000)` `    await page.goto(url, timeout=10000, wait_until=\"domcontentloaded\")` `finally:` `    await context.close()` |
| `BRW-010` | Download Restrictions: автоскачивание включено, MIME не проверяется | `context = await browser.new_context(accept_downloads=False)` `page = await context.new_page()` `resp = await page.goto(url, wait_until=\"domcontentloaded\")` `content_type = (resp.headers.get(\"content-type\", \"\") if resp else \"\")` `allowed = {\"text/html\", \"application/json\"}` `if content_type.split(\";\")[0] not in allowed:` `    raise ValueError(\"blocked MIME type\")` |
| `BRW-011` | DOM XSS: пользовательский контент вставляется через `innerHTML` | `const note = request.body.note` `...` `await page.evaluate((value) => { document.querySelector("#out").textContent = value }, note)` |
| `BRW-012` | JS Injection: выполнение пользовательского JS через `eval`/`new Function` | `const cmd = request.body.cmd` `allowed = {"scrollTop":"window.scrollTo(0,0)"}` `if (!(cmd in allowed)) throw new Error("cmd rejected")` `...` `await page.evaluate(allowed[cmd])` |
| `BRW-013` | Prototype Pollution: запись в `__proto__` / merge без фильтра ключей | `const patch = request.body.patch` `for (const k of Object.keys(patch)) {` `  if (["__proto__","constructor","prototype"].includes(k)) throw new Error("blocked key")` `}` `...` `Object.assign(config, patch)` |

## Verification

**Verification:** Check the gold testbed file(s) below for `Vulnerable: <ID>` markers (static Semgrep + `detection-matrix.md` ground truth).

- [`gold-standard-testbed/browser_vulnerable.js`](../gold-standard-testbed/browser_vulnerable.js)

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

