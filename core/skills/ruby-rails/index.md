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
| `RUB-001` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-002` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-003` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-004` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-005` | Semgrep: http-client-requests | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-006` | Semgrep: net-http-request | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-007` | Semgrep: net-telnet-request | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-008` | Semgrep: openuri-request | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-009` | Semgrep: activerecord-sqli | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-010` | Semgrep: mysql2-sqli | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-011` | Semgrep: sequel-sqli | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-012` | Semgrep: tainted-deserialization | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-013` | Semgrep: ruby-jwt-decode-without-verify | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-014` | Semgrep: ruby-jwt-exposed-data | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-015` | Semgrep: bad-deserialization-env | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-016` | Semgrep: bad-deserialization-yaml | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-017` | Semgrep: cookie-serialization | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-018` | Semgrep: create-with | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-019` | Semgrep: dangerous-exec | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-020` | Semgrep: dangerous-subshell | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-021` | Semgrep: divide-by-zero | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-022` | Semgrep: file-disclosure | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-023` | Semgrep: force-ssl-false | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-024` | Semgrep: hardcoded-http-auth-in-controller | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-025` | Semgrep: hardcoded-secret-rsa-passphrase | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-026` | Semgrep: insufficient-rsa-key-size | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-027` | Semgrep: json-entity-escape | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-028` | Semgrep: mass-assignment-protection-disabled | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-029` | Semgrep: missing-csrf-protection | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-030` | Semgrep: model-attr-accessible | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-031` | Semgrep: model-attributes-attr-accessible | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-032` | Semgrep: ruby-eval | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-033` | Semgrep: ssl-mode-no-verify | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-034` | Semgrep: mass-assignment-vuln | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-035` | Semgrep: weak-hashes-sha1 | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-036` | Semgrep: Found a call to `render $T` after calling `$T.save`. Do not call `render` | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-037` | Semgrep: Avoid logging `params` and `params.inspect` as this bypasses Rails filter_para... | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-038` | Semgrep: avoid-session-manipulation | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-039` | Semgrep: avoid-tainted-file-access | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-040` | Semgrep: avoid-tainted-ftp-call | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-041` | Semgrep: avoid-tainted-http-request | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-042` | Semgrep: avoid-tainted-shell-call | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-043` | Semgrep: detailed-exceptions | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-044` | Semgrep: This call turns off CSRF protection allowing CSRF attacks against the application | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-045` | Semgrep: ruby-pg-sqli | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-046` | Semgrep: avoid-link-to | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-047` | Semgrep: avoid-redirect | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-048` | Semgrep: avoid-render-dynamic-path | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-049` | Semgrep: avoid-render-inline | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-050` | Semgrep: avoid-render-text | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-051` | Semgrep: libxml-backend | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-052` | Semgrep: xml-external-entities-enabled | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-053` | Semgrep: Disabled-by-default Rails controller checks make it much easier to introduce a... | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-054` | Semgrep: Found an improperly constructed control flow block with `request.get?`. Rails ... | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-055` | Semgrep: Calling `permit` on security-critical properties like `$ATTRIBUTE` may leave y... | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-056` | Semgrep: Calling `permit` on security-critical properties like `$ATTRIBUTE` may leave y... | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-057` | Semgrep: Found a string literal assignment to a Rails session secret `$KEY`. Do not com... | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-058` | Semgrep: Found potentially unsafe handling of redirect behavior $X. Do not pass `params... | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-059` | Semgrep: check-regex-dos | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-060` | Semgrep: Found request parameters in a call to `render`. This can allow end | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-061` | Semgrep: check-secrets | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-062` | Semgrep: Allowing user input to `send_file` allows a malicious user to potentially read... | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-063` | Semgrep: Found potential SQL injection due to unsafe SQL query construction via $X. Whe... | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-064` | Semgrep: Found user-controllable input to a reflection method. This may allow a user to... | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `RUB-065` | Semgrep: $V Found an incorrectly-bounded regex passed to `validates_format_of` or `vali... | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |

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

