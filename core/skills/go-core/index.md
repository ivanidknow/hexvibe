# Go Core

## Stack overview

**Go** services: `net/http`, SQL/ORM, gRPC, `unsafe`/CGO edges, and concurrency. Metrics are prefixed **`GO`**.

## Top threats

- Command injection and unsafe `exec` (`GO-001`–`GO-008`, `GO-021`).
- SSRF, path traversal, open redirect (`GO-010`, `GO-011`, `GO-014`, `GO-026`).
- Weak crypto and JWT mistakes (`GO-013`, `GO-016`, `GO-018`, `GO-031`, `GO-040`).
- Concurrency and resource limits (`GO-009`, `GO-019`, `GO-023`, `GO-030`, `GO-032`).

## Pattern catalog

Complete Anti-Pattern / Safe-Pattern definitions live in [`patterns.md`](patterns.md). The table below is a **table of contents** by metric ID.

| ID | Metric | Stack |
|---|---|---|
| `GO-001` | Command Injection: `exec.Command("sh","-c", userInput)` | `action := r.URL.Query().Get("action")` `allowed := map[string][]string{"uptime": {"uptime"}}` `...` `exec.Command(allowed[action][0]).Run()` |
| `GO-002` | OS Exec Injection: `exec.Command("bash","-c",...)` с конкатенацией | `host := r.URL.Query().Get("host")` `if !hostRe.MatchString(host) { return }` `...` `exec.Command("ping", "-c", "1", host).Run()` |
| `GO-003` | Unsafe SQL Fragment Injection | `order := r.URL.Query().Get("order")` `if order != "name" && order != "created_at" { order = "name" }` `...` `q := "SELECT * FROM users ORDER BY " + order` |
| `GO-004` | Unsafe Reflection by Name | `m := r.URL.Query().Get("method")` `if m != "Health" && m != "Status" { return }` `...` `reflect.ValueOf(handler).MethodByName(m).Call(nil)` |
| `GO-005` | Plugin Loading from User Input | `name := r.URL.Query().Get("plugin")` `if _, ok := allowedPlugins[name]; !ok { return }` `...` `plugin.Open(allowedPlugins[name])` |
| `GO-006` | JavaScript Injection via goja/otto eval | `cmd := r.FormValue("cmd")` `if cmd != "normalize" { return }` `...` `vm.RunString("normalize(input)")` |
| `GO-007` | Template Expression Injection | `name := r.FormValue("template")` `if _, ok := safeTemplates[name]; !ok { return }` `...` `template.Must(template.ParseFiles(safeTemplates[name]))` |
| `GO-008` | Unsafe Command Router from User Field | `tool := payload["tool"]` `allowed := map[string][]string{"date": {"date"}}` `if _, ok := allowed[tool.(string)]; !ok { return }` `...` `exec.Command(allowed[tool.(string)][0]).Run()` |
| `GO-009` | Goroutine Leak: бесконечная goroutine без `context`-остановки | `go func(ctx context.Context) {` `    for {` `        select {` `        case <-ctx.Done():` `            return` `        default:` `            ...` `        }` `    }` `}(ctx)` |
| `GO-010` | Path Traversal: небезопасный путь через `filepath.Join(root, userInput)` | `name := r.URL.Query().Get("file")` `clean := filepath.Clean("/" + name)` `target := filepath.Join(root, clean)` `if !strings.HasPrefix(target, root) {` `    return` `}` |
| `GO-011` | SSRF: прямой `http.Get(userInputURL)` | `url := r.URL.Query().Get("url")` `host := parseHost(url)` `allowed := map[string]bool{"api.example.com": true}` `if !allowed[host] {` `    return` `}` `resp, _ := http.Get(url)` |
| `GO-012` | Unsafe Pointer Conversion: арифметика через `unsafe.Pointer` | `buf := make([]byte, n)` `...` `_ = buf[offset:]` `// avoid unsafe pointer arithmetic` |
| `GO-013` | Weak Crypto: использование MD5/SHA1 | `...` `h := sha256.New()` |
| `GO-014` | Open Redirect: redirect на URL из query без проверки | `next := r.URL.Query().Get("next")` `if !isRelativeOrAllowed(next) {` `    next = "/"` `}` `http.Redirect(w, r, next, http.StatusFound)` |
| `GO-015` | Log Injection: CR/LF в логах из пользовательского ввода | `userInput := r.URL.Query().Get("user")` `safe := strings.NewReplacer("\\n", "\\\\n", "\\r", "\\\\r").Replace(userInput)` `...` `log.Printf("User: %s", safe)` |
| `GO-016` | Hardcoded Credentials: секреты в константах/строках | `apiKey := os.Getenv("API_KEY")` `if apiKey == "" {` `    panic("missing API_KEY")` `}` |
| `GO-017` | Data Race: запись в общую переменную без `Mutex` | `...` `mu.Lock()` `counter = counter + 1` `mu.Unlock()` |
| `GO-018` | JWT Signature Validation Bypass: отсутствие проверки `alg` в `Keyfunc` | `token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {` `    if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {` `        return nil, fmt.Errorf("unexpected signing method")` `    }` `    return key, nil` `})` |
| `GO-019` | DB Connection Leak: `db.Query` без `defer rows.Close()` | `rows, err := db.Query(query)` `if err != nil {` `    return err` `}` `defer rows.Close()` `...` |
| `GO-020` | Insecure TLS Config: `InsecureSkipVerify: true` | `tr := &http.Transport{` `    TLSClientConfig: &tls.Config{InsecureSkipVerify: false},` `}` |
| `GO-021` | Unclosed File/Resource: `os.Open` без `defer Close()` | `f, err := os.Open(path)` `if err != nil {` `    return err` `}` `defer f.Close()` `...` |
| `GO-022` | Improper Output Encoding (XSS): небезопасный вывод пользовательского ввода | `tmpl := template.Must(template.New("x").Parse("Hello {{.Name}}"))` `...` `tmpl.Execute(w, map[string]string{"Name": name})` |
| `GO-023` | Missing Request Body Limit: чтение тела без лимита | `body, _ := io.ReadAll(io.LimitReader(r.Body, maxBytes))` `...` `_ = body` |
| `GO-024` | Debug Endpoint in Production: подключен `pprof` без feature flag | `if debugEnabled {` `    mux := http.NewServeMux()` `    ...` `    http.ListenAndServe("127.0.0.1:6060", mux)` `}` |
| `GO-025` | gRPC Missing Auth: RPC метод без проверки metadata/auth | `srv := grpc.NewServer(grpc.UnaryInterceptor(grpc_auth.UnaryServerInterceptor(authFunc)))` `...` `func authFunc(ctx context.Context) (context.Context, error) {` `    md, _ := metadata.FromIncomingContext(ctx)` `    ...` `    return ctx, nil` `}` |
| `GO-026` | Zip Slip: распаковка архива без проверки пути назначения | `for _, f := range zipReader.File {` `    targetPath := filepath.Join(dest, f.Name)` `    clean := filepath.Clean(targetPath)` `    if !strings.HasPrefix(clean, filepath.Clean(dest)+string(os.PathSeparator)) {` `        return fmt.Errorf("zip slip detected")` `    }` `    writeFile(clean, f)` `}` |
| `GO-027` | HTTP Proxy Header Injection: прямой прокси hop-by-hop заголовков | `proxy := &httputil.ReverseProxy{` `    Director: func(req *http.Request) {` `        ...` `        req.Header = cloneAllowedHeaders(r.Header)` `        stripHopByHop(req.Header)` `    },` `}` |
| `GO-028` | Unsafe Reflect-based Deep Copy: рекурсивный `reflect` без type-guard | `func CopyMessage(msg proto.Message) proto.Message {` `    ...` `    return proto.Clone(msg)` `}` |
| `GO-029` | Hardcoded Root CAs: встроенные PEM в `tls.Config` | `pem, err := os.ReadFile("/etc/ssl/certs/internal-ca.pem")` `...` `pool.AppendCertsFromPEM(pem)` |
| `GO-030` | gRPC Message Size Limit Missing: сервер без `MaxRecvMsgSize` | `srv := grpc.NewServer(grpc.MaxRecvMsgSize(4*1024*1024))` `...` `pb.RegisterApiServer(srv, api)` |
| `GO-031` | Insecure Randomness: `math/rand` для токенов/секретов | `b := make([]byte, 32)` `...` `if _, err := cryptorand.Read(b); err != nil {` `    return err` `}` |
| `GO-032` | Unbounded JSON Unmarshal: парсинг тела запроса без ограничения размера | `raw, _ := io.ReadAll(io.LimitReader(r.Body, maxBytes))` `...` `json.Unmarshal(raw, &payload)` |
| `GO-033` | GORM Raw SQL Injection: конкатенация в `.Where()`/`.Raw()` | `name := r.URL.Query().Get("name")` `...` `db.Where("name = ?", name).Find(&users)` `...` `db.Raw("SELECT * FROM users WHERE name = ?", name).Scan(&users)` |
| `GO-034` | Bypassing XSS protection via `template.HTML` | `input := r.URL.Query().Get("html")` `tmpl := template.Must(template.New("x").Parse("{{.Content}}"))` `...` `tmpl.Execute(w, map[string]string{"Content": input})` |
| `GO-035` | Sensitive Info Leak in Error Messages | `err := someInternalError` `...` `log.Printf("internal error: %v", err)` `return errors.New("internal server error")` |
| `GO-036` | Unsafe CGO Buffer: указатели в C без валидации буфера | `buf := []byte(input)` `cbuf := C.CBytes(buf)` `defer C.free(cbuf)` `...` `C.process(cbuf)` |
| `GO-037` | Prototype Pollution / Map Assignment: копирование JSON-ключей без валидации | `allowed := map[string]bool{"name": true, "email": true}` `for k, v := range incomingMap {` `    if allowed[k] {` `        targetMap[k] = v` `    }` `}` |
| `GO-038` | Improper XML Entity Handling: парсер с дефолтными внешними сущностями | `xmlParser := customxml.NewParser()` `...` `xmlParser.DisableExternalEntities(true)` `xmlParser.Parse(rawXML)` |
| `GO-039` | Regex DoS (ReDoS): сложный regex на длинном пользовательском вводе | `if len(longUserInput) > 2048 {` `    return` `}` `re := regexp.MustCompile(userRegex)` `...` `re.MatchString(longUserInput)` |
| `GO-040` | Hardcoded JWT Secret: ключ подписи зашит в коде | `jwtKey := []byte(os.Getenv("JWT_SECRET"))` `if len(jwtKey) == 0 {` `    panic("missing JWT_SECRET")` `}` |

## Verification

**Verification:** Check the gold testbed file(s) below for `Vulnerable: <ID>` markers (static Semgrep + `detection-matrix.md` ground truth).

- [`gold-standard-testbed/multi_lang_vulnerable/go_vulnerable.go`](../gold-standard-testbed/multi_lang_vulnerable/go_vulnerable.go)

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

