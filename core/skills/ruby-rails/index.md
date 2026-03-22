# Ruby / Rails

## Stack overview

**Rails**-style controllers and Ruby idioms: `eval`, YAML, mass assignment, redirects, and SSRF. Metrics are prefixed **`RUBY`**.

## Top threats

- Code/command injection and ERB (`RUBY-001`–`RUBY-003`, `RUBY-006`, `RUBY-012`).
- Unsafe YAML and mass assignment (`RUBY-008`–`RUBY-011`).
- Open redirect, cookies, SSRF (`RUBY-013`–`RUBY-014`, `RUBY-017`).

## Pattern catalog

Complete Anti-Pattern / Safe-Pattern definitions live in [`patterns.md`](patterns.md). The table below is a **table of contents** by metric ID.

| ID | Metric | Stack |
|---|---|---|
| `RUBY-001` | Ruby Code Injection: `eval(params[:expr])` | `expr = params[:expr]` `raise "invalid" unless expr =~ /\\A[0-9+\\-*\\/(). ]{1,64}\\z/` `...` `result = safe_math_eval(expr)` |
| `RUBY-002` | Command Injection: `system(params[:cmd])` | `action = params[:action]` `allowed = { "uptime" => ["uptime"] }` `raise "blocked" unless allowed.key?(action)` `...` `Open3.capture2e(*allowed[action])` |
| `RUBY-003` | Shell Injection: backticks with user input | `host = params[:host]` `raise "invalid" unless host =~ /\\A[a-zA-Z0-9.-]{1,255}\\z/` `...` `out, _ = Open3.capture2e("ping", "-c", "1", host)` |
| `RUBY-004` | Unsafe Constantize: класс из params | `allow = { "HealthHandler" => HealthHandler }` `key = params[:klass]` `raise "blocked" unless allow.key?(key)` `...` `allow[key].new.call` |
| `RUBY-005` | Unsafe `send` from user method name | `method = params[:method]` `allowed = %w[health status]` `raise "blocked" unless allowed.include?(method)` `...` `service.public_send(method)` |
| `RUBY-006` | ERB Injection: шаблон из пользовательского ввода | `name = params[:template_name]` `allowed = %w[welcome invoice]` `raise "blocked" unless allowed.include?(name)` `...` `render template: "safe/#{name}"` |
| `RUBY-007` | SQL Fragment Injection: dynamic ORDER BY | `order = params[:order]` `order = "name" unless %w[name created_at].include?(order)` `...` `User.order(order)` |
| `RUBY-008` | Unsafe YAML deserialization in command flow | `blob = params[:blob]` `...` `obj = YAML.safe_load(blob, permitted_classes: [], aliases: false)` |
| `RUBY-009` | Mass Assignment: критичные поля принимаются напрямую из params | `allowed = params.require(:user).permit(:email, :display_name)` `user.update(allowed)` |
| `RUBY-010` | Unsafe Render Path: путь шаблона из пользовательского ввода | `name = params[:name]` `raise "blocked" unless %w[home about].include?(name)` `render template: "pages/#{name}"` |
| `RUBY-011` | YAML.load Deserialization: небезопасная загрузка объектов | `obj = YAML.safe_load(params[:payload], permitted_classes: [], aliases: false)` |
| `RUBY-012` | Command Injection через backticks | `allowed = {"uptime" => ["uptime"]}` `cmd = params[:action]` `raise "blocked" unless allowed.key?(cmd)` `Open3.capture2e(*allowed[cmd])` |
| `RUBY-013` | Open Redirect в контроллере | `next_url = params[:next]` `next_url = root_path unless next_url&.start_with?("/")` `redirect_to next_url` |
| `RUBY-014` | Insecure Cookies: отсутствие HttpOnly/Secure | `cookies[:session] = { value: token, httponly: true, secure: true, same_site: :strict }` |
| `RUBY-015` | Hardcoded Secret in initializer | `JWT_SECRET = ENV.fetch("JWT_SECRET")` |
| `RUBY-016` | Weak Crypto Digest (MD5/SHA1) | `Digest::SHA256.hexdigest(password + salt)` |
| `RUBY-017` | SSRF через Net::HTTP на URL из params | `uri = URI(params[:url])` `raise "blocked" unless ALLOWED_HOSTS.include?(uri.host)` `Net::HTTP.get(uri)` |
| `RUBY-018` | Unsafe Constantize from params | `allow = {"ReportJob" => ReportJob}` `klass = allow.fetch(params[:klass])` |
| `RUBY-019` | Debug endpoint in production | `if Rails.env.development?` `  get "/debug/env", to: "debug#env"` `end` |
| `RUBY-020` | Sensitive error leakage наружу | `Rails.logger.error(e.full_message)` `render json: { error: "internal server error" }, status: 500` |

## Verification

**Verification:** Check the gold testbed file(s) below for `Vulnerable: <ID>` markers (static Semgrep + `detection-matrix.md` ground truth).

- [`gold-standard-testbed/multi_lang_vulnerable/ruby_vulnerable.rb`](../gold-standard-testbed/multi_lang_vulnerable/ruby_vulnerable.rb)

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

