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
| `GO-041` | GraphQL: Missing query depth limit enables recursive DoS | `CWE-400` |
| `GO-042` | GraphQL: Circular fragment recursion not detected | `CWE-674` |
| `GO-043` | GraphQL: Missing field-level AuthZ in resolver | `CWE-285` |
| `GO-044` | GraphQL: Introspection enabled in production for untrusted clients | `CWE-200` |
| `GO-045` | GraphQL: Unbounded complexity score causes CPU exhaustion | `CWE-400` |
| `GO-046` | gRPC stream deadlock via bidirectional channel misuse (Logic: strong) | `CWE-833` |
| `GO-047` | gRPC unauthenticated metadata reflection endpoint | `CWE-306` |
| `GO-048` | gRPC missing protobuf payload size guard | `CWE-770` |
| `GO-049` | gRPC metadata spoofing via trusted x-user-id header | `CWE-290` |
| `GO-050` | gRPC interceptor chain allows unauthenticated fallback | `CWE-306` |
| `GO-051` | GraphQL DataLoader cache shared across tenants | `CWE-639` |
| `GO-052` | GraphQL subscription lacks connection-level auth revalidation | `CWE-287` |
| `GO-053` | GraphQL alias amplification bypasses resolver quotas | `CWE-770` |
| `GO-054` | Protobuf Any deserialization accepts arbitrary type URLs | `CWE-502` |
| `GO-055` | gRPC stream handler leaks goroutines on client disconnect | `CWE-400` |
| `GO-056` | Financial ledger update race in concurrent transfer (Logic: strong) | `CWE-362` |
| `GO-057` | TOCTOU race in idempotency key check for payouts (Logic: strong) | `CWE-367` |
| `GO-058` | GraphQL persisted query cache poisoning across environments | `CWE-349` |
| `GO-059` | gRPC deadline ignored causing worker pool exhaustion | `CWE-400` |
| `GO-060` | gRPC reflection service exposed on public listener | `CWE-200` |
| `GOX-101` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-102` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-103` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-104` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-105` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-106` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-107` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-108` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-109` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-110` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-111` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-112` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-113` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-114` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-115` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-116` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-117` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-118` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-119` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-120` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-121` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-122` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-123` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-124` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-125` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-126` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-127` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-128` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-129` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-130` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-131` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-132` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-133` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-134` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-135` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-136` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-137` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-138` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-139` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-140` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-141` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-142` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-143` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-144` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-145` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-146` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-147` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-148` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-149` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-150` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-151` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-152` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-153` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-154` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-155` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-156` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-157` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-158` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-159` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-160` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-161` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-162` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-163` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-164` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-165` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-166` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-167` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-168` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-169` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-170` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-171` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-172` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-173` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-174` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-175` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-176` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-177` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-178` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-179` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-180` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-181` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-182` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-183` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-184` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-185` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-186` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-187` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-188` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-189` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-190` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-191` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-192` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-193` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-194` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-195` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-196` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-197` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-198` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-199` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-200` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-201` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-202` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-203` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-204` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-205` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-206` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-207` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-208` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-209` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-210` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-211` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-212` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-213` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-214` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-215` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-216` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-217` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-218` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-219` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-220` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-221` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-222` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-223` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-224` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-225` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-226` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-227` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-228` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-229` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-230` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-231` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-232` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-233` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-234` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-235` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-236` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-237` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-238` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-239` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-240` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-241` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-242` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-243` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-244` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-245` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-246` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-247` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-248` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-249` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-250` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-251` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-252` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-253` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-254` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-255` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-256` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-257` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-258` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-259` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-260` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-261` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-262` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-263` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-264` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-265` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-266` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-267` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-268` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-269` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-270` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-271` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-272` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-273` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-274` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-275` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-276` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-277` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-278` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-279` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-280` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-281` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-282` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-283` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-284` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-285` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-286` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-287` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-288` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-289` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-290` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-291` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-292` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-293` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-294` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-295` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-296` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-297` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-298` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-299` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-300` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-301` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-302` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-303` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-304` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-305` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GOX-306` | Mutex missing around shared state in goroutine (CWE-662) | Autofix: wrap shared state writes with mutex lock and unlock. |
| `GOX-307` | Interface nil dereference in auth handler flow | Autofix: add nil guard for interface dependencies before method calls. |
| `GOX-308` | Go BOLA: tenant object fetched by request id only (Logic: strong) | Autofix: enforce tenant-bound ID resolver before object access. |
| `GOX-309` | Go mass assignment from JSON map into struct (Logic: strong) | Autofix: map only trusted keys instead of arbitrary payload map iteration. |
| `GOX-310` | Missing WaitGroup accounting leaks goroutines | Autofix: add WaitGroup lifecycle around spawned goroutines. |
| `GO-061` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-062` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-063` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-064` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-065` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-066` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-067` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-068` | Semgrep: Found SameSiteNoneMode setting in Gorilla session options. Consider setting | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-069` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-070` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-071` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-072` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-073` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-074` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-075` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-076` | Semgrep: Detected conversion of the result of a strconv.Atoi command to an int16. This ... | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-077` | Semgrep: Detected conversion of the result of a strconv.Atoi command to an int16. This ... | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-078` | Semgrep: `path.Join(...)` always joins using a forward slash. This may cause | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-079` | Semgrep: Detected useless comparison operation `$X == $X` or `$X != $X`. This will alwa... | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-080` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-081` | Semgrep: Do not use `math/rand`. Use `crypto/rand` instead. | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-082` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-083` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-084` | Semgrep: RSA keys should be at least 2048 bits | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-085` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-086` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-087` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-088` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-089` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-090` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-091` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-092` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-093` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-094` | Semgrep: Detected string concatenation with a non-literal variable in a go-pg | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-095` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-096` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-097` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-098` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-099` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-100` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-101` | Semgrep: File creation in shared tmp directory without using `io.CreateTemp`. | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-102` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-103` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-104` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-105` | Semgrep: A request was found to be crafted from user-input `$REQUEST`. This can | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-106` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-107` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-108` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-109` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-110` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-111` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-112` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-113` | Semgrep: >- | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-114` | Semgrep: grequests-http-request | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-115` | Semgrep: http-customized-request | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-116` | Semgrep: http-request | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-117` | Semgrep: sling-http-request | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-118` | Semgrep: telnet-request | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `GO-119` | Semgrep: Using input or workflow parameters in here-scripts can lead to command injecti... | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |

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

