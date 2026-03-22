# Fortress v13.1: Full 550-Rule Remediation Report

Baseline: 550 rules | Hits: 550 | Misses: 0.

Generated from `core/skills/*/patterns.md` with full Safe-Pattern mapping for every metric ID.

Coverage note: categories `K8S`, `SQD`, `NGX`, `DOCK` are included in this report.

## Full ID Catalog

### AAC-001 — SSRF in Playwright

- Source: `core/skills/advanced-agent-cloud/patterns.md`
- Safe-Pattern: `ALLOWED_HOSTS = {"cdn.example.com"}`<br>`u = urlparse(userInput)`<br>`if u.hostname not in ALLOWED_HOSTS: raise ValueError("url not allowed")`<br>`await page.goto(userInput)`

### AAC-002 — Leakage in Playwright Traces

- Source: `core/skills/advanced-agent-cloud/patterns.md`
- Safe-Pattern: `await context.tracing.start(screenshots=False)` или маскирование PII перед экспортом трейса

### AAC-003 — Next.js Client-side Secret Leak

- Source: `core/skills/advanced-agent-cloud/patterns.md`
- Safe-Pattern: `const key = process.env.STRIPE_SECRET_KEY` (только серверные модули / Route Handlers без `NEXT_PUBLIC_`)

### AAC-004 — Insecure RQ (Redis Queue) Job

- Source: `core/skills/advanced-agent-cloud/patterns.md`
- Safe-Pattern: `json.loads(raw_job)` или `msgpack.loads` + явная схема данных

### AAC-005 — Insecure MinIO Pre-signed URL

- Source: `core/skills/advanced-agent-cloud/patterns.md`
- Safe-Pattern: `expires=timedelta(seconds=45)` + проверка владельца объекта и `method` GET-only где возможно

### AAC-006 — Keycloak SSO Bypass

- Source: `core/skills/advanced-agent-cloud/patterns.md`
- Safe-Pattern: `claims = jwt.decode(token, key, audience=..., issuer=..., options={"verify_exp": True})`

### AAC-007 — Nginx Rate Limit Missing

- Source: `core/skills/advanced-agent-cloud/patterns.md`
- Safe-Pattern: `limit_req zone=api burst=20 nodelay;` в том же `location` или выше по цепочке

### AAC-008 — Egress Proxy Bypass (Squid)

- Source: `core/skills/advanced-agent-cloud/patterns.md`
- Safe-Pattern: `HTTP_PROXY`/`HTTPS_PROXY` заданы на уровне контейнера; `Session(trust_env=True)`

### AAC-009 — Log Injection in Task Queues

- Source: `core/skills/advanced-agent-cloud/patterns.md`
- Safe-Pattern: `logger.info("job=%s", sanitize(redis_raw_payload))`

### AAC-010 — Insecure WebRTC/VAD Permissions

- Source: `core/skills/advanced-agent-cloud/patterns.md`
- Safe-Pattern: state-machine: явное `consentGiven === true` до вызова `getUserMedia`

### AK-001 — Weak Algorithm: разрешен `alg=none` или нефиксированный алгоритм

- Source: `core/skills/auth-keycloak/patterns.md`
- Safe-Pattern: `from jose import jwt`<br>`header = jwt.get_unverified_header(token)`<br>`if header.get(\"alg\") not in {\"RS256\", \"ES256\", \"GOST3410\"}:`<br>`    raise ValueError(\"unsupported alg\")`<br>`claims = jwt.decode(`<br>`    token,`<br>`    jwk,`<br>`    algorithms=[\"RS256\", \"ES256\", \"GOST3410\"],`<br>`    issuer=issuer_url,`<br>`    audience=client_id,`<br>`    options={\"verify_signature\": True},`<br>`)`<br>`# для контура Клинкера включить профиль российских криптоалгоритмов (ГОСТ)`

### AK-002 — Issuer/Audience Mismatch: невалидируемые `iss` и `aud`

- Source: `core/skills/auth-keycloak/patterns.md`
- Safe-Pattern: `import jwt`<br>`claims = jwt.decode(`<br>`    token,`<br>`    pub_key,`<br>`    algorithms=[\"RS256\", \"ES256\"],`<br>`    issuer=issuer_url,`<br>`    audience=client_id,`<br>`    options={\"verify_signature\": True, \"verify_exp\": True, \"verify_nbf\": True, \"verify_iat\": True},`<br>`)`

### AK-003 — JWS Header Injection: прямое доверие `kid` из заголовка

- Source: `core/skills/auth-keycloak/patterns.md`
- Safe-Pattern: `header = jwt.get_unverified_header(token)`<br>`kid = header.get(\"kid\")`<br>`trusted_kids = {k[\"kid\"] for k in jwks[\"keys\"]}`<br>`if kid not in trusted_kids:`<br>`    raise ValueError(\"untrusted kid\")`<br>`jwk = next(k for k in jwks[\"keys\"] if k[\"kid\"] == kid)`<br>`claims = jwt.decode(token, jwk, algorithms=[\"RS256\", \"ES256\"], issuer=issuer_url, audience=client_id)`

### AK-004 — Insecure Redirects: wildcard и нет точного HTTPS-match

- Source: `core/skills/auth-keycloak/patterns.md`
- Safe-Pattern: `allowed_redirects = {`<br>`    \"https://app.example.com/oidc/callback\",`<br>`    \"https://admin.example.com/oidc/callback\",`<br>`}`<br>`if redirect_uri not in allowed_redirects:`<br>`    raise ValueError(\"redirect_uri mismatch\")`

### AK-005 — Client Secret Exposure: secret захардкожен в коде

- Source: `core/skills/auth-keycloak/patterns.md`
- Safe-Pattern: `import os`<br>`from keycloak import KeycloakOpenID`<br>`kc = KeycloakOpenID(`<br>`    server_url=os.environ[\"KEYCLOAK_URL\"],`<br>`    realm_name=os.environ[\"KEYCLOAK_REALM\"],`<br>`    client_id=os.environ[\"KEYCLOAK_CLIENT_ID\"],`<br>`    client_secret_key=os.environ[\"KEYCLOAK_CLIENT_SECRET\"],`<br>`)`

### AK-006 — Subject Confusion: `sub` не связан с текущим пользователем

- Source: `core/skills/auth-keycloak/patterns.md`
- Safe-Pattern: `claims = jwt.decode(token, jwk, algorithms=[\"RS256\", \"ES256\"], issuer=issuer_url, audience=client_id, options={\"verify_exp\": True, \"verify_nbf\": True, \"verify_iat\": True})`<br>`user = db.get_user_by_id(current_user_id)`<br>`if claims.get(\"sub\") != user.oidc_sub:`<br>`    raise ValueError(\"subject mismatch\")`

### AK-007 — Authorization Code не привязан к `redirect_uri` и `client_id`

- Source: `core/skills/auth-keycloak/patterns.md`
- Safe-Pattern: `assert request_client_id == stored_client_id_for_code(code)`<br>`assert request_redirect_uri == stored_redirect_uri_for_code(code)`<br>`token = exchange_code_for_token(code=code, client_id=request_client_id, redirect_uri=request_redirect_uri)`

### AK-008 — Нет обязательной проверки времени жизни токена (`exp/nbf/iat`)

- Source: `core/skills/auth-keycloak/patterns.md`
- Safe-Pattern: `claims = jwt.decode(token, jwk, algorithms=[\"RS256\", \"ES256\"], issuer=issuer_url, audience=client_id, options={\"verify_exp\": True, \"verify_nbf\": True, \"verify_iat\": True})`

### AK-009 — PKCE Enforcement: Authorization Code Flow без `code_challenge`/`code_verifier`

- Source: `core/skills/auth-keycloak/patterns.md`
- Safe-Pattern: `auth_url = f"{issuer}/protocol/openid-connect/auth?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}&code_challenge={code_challenge}&code_challenge_method=S256"`<br>`token = exchange_code(code=code, code_verifier=code_verifier)`<br>`if not code_verifier:`<br>`    raise ValueError("pkce required")`

### AK-010 — DPoP отсутствует для высокорисковых операций (Token Theft risk)

- Source: `core/skills/auth-keycloak/patterns.md`
- Safe-Pattern: `def call_high_risk_api(access_token: str, dpop_proof: str):`<br>`    if not dpop_proof:`<br>`        raise ValueError("DPoP proof required")`<br>`    return client.post("/payments/transfer", headers={"Authorization": f"Bearer {access_token}", "DPoP": dpop_proof})`<br>`# DPoP обязателен для высокорисковых операций ЦБ, чтобы снизить риск кражи токенов`

### AK-011 — PII in JWT: конфиденциальные данные в открытом payload

- Source: `core/skills/auth-keycloak/patterns.md`
- Safe-Pattern: `payload = {"sub": user_id, "role": role, "scope": "api.read"}`<br>`token = jwt.encode(payload, private_key, algorithm="RS256")`<br>`# PII moved to userinfo endpoint or encrypted storage`

### AK-012 — JWKS Rate Limiting: нет ограничений на запросы к `/.well-known/jwks.json` при неизвестном `kid`

- Source: `core/skills/auth-keycloak/patterns.md`
- Safe-Pattern: `def get_jwk_for_kid(kid: str):`<br>`    if kid in negative_kid_cache and not negative_kid_cache[kid].expired:`<br>`        raise ValueError("unknown kid cached")`<br>`    if not jwks_rate_limiter.allow("jwks_fetch"):`<br>`        raise RuntimeError("jwks rate limit exceeded")`<br>`    jwks = requests.get(f"{issuer}/.well-known/jwks.json", timeout=2).json()`<br>`    # cache keys and unknown kid misses`<br>`    return select_key_from_jwks(jwks, kid)`

### AK-013 — Insecure Token Forwarding: прямой проброс пользовательского JWT между микросервисами

- Source: `core/skills/auth-keycloak/patterns.md`
- Safe-Pattern: `def exchange_token(user_jwt: str, audience: str) -> str:`<br>`    resp = requests.post(f"{issuer}/protocol/openid-connect/token", data={`<br>`        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",`<br>`        "subject_token": user_jwt,`<br>`        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",`<br>`        "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",`<br>`        "audience": audience,`<br>`    }, auth=(client_id, client_secret), cert=(client_cert_path, client_key_path), timeout=5)`<br>`    resp.raise_for_status()`<br>`    return resp.json()["access_token"]`<br><br>`def call_internal_service(user_jwt: str):`<br>`    svc_token = exchange_token(user_jwt, audience="orders-api")`<br>`    return requests.get("http://orders.internal/api/orders", headers={"Authorization": f"Bearer {svc_token}"}, timeout=5)`<br>`# token exchange endpoint /token вызывать только по mTLS в профиле ФАПИ.ПАОК`

### AK-014 — Missing Resource Indicators: отсутствует параметр `resource` при запросе токена

- Source: `core/skills/auth-keycloak/patterns.md`
- Safe-Pattern: `token_req = {`<br>`    "grant_type": "authorization_code",`<br>`    "code": code,`<br>`    "redirect_uri": redirect_uri,`<br>`    "resource": "https://api.example.com/orders",`<br>`}`<br>`token = requests.post(token_url, data=token_req, auth=(client_id, client_secret), timeout=5)`<br>`token.raise_for_status()`

### AK-015 — OIDC State Validation Missing: callback не проверяет `state`

- Source: `core/skills/auth-keycloak/patterns.md`
- Safe-Pattern: `@app.get("/oidc/callback")`<br>`async def callback(code: str, state: str, request: Request):`<br>`    expected = request.session.get("oidc_state")`<br>`    if not expected or state != expected:`<br>`        raise HTTPException(status_code=401, detail="invalid state")`<br>`    ...`<br>`    return await exchange_code(code)`

### AK-016 — OIDC Nonce Validation Missing: ID Token принимается без проверки `nonce`

- Source: `core/skills/auth-keycloak/patterns.md`
- Safe-Pattern: `id_claims = jwt.decode(id_token, jwk, algorithms=["RS256","ES256"], audience=client_id, issuer=issuer)`<br>`expected_nonce = request.session.get("oidc_nonce")`<br>`if not expected_nonce or id_claims.get("nonce") != expected_nonce:`<br>`    raise HTTPException(status_code=401, detail="invalid nonce")`<br>`...`<br>`return id_claims`

### AK-017 — Session Management: нет принудительного logout и refresh_token TTL > 24ч

- Source: `core/skills/auth-keycloak/patterns.md`
- Safe-Pattern: `refresh_token_ttl = 86400`<br>`if refresh_token_ttl > 86400:`<br>`    raise ValueError("CB session limit exceeded")`<br>`enable_backchannel_logout = True`<br>`enable_frontchannel_logout = True`<br>`revoke_refresh_token_on_logout = True`

### AK-018 — Zero Trust mTLS: межсервисные вызовы выполняются без mTLS

- Source: `core/skills/auth-keycloak/patterns.md`
- Safe-Pattern: Все межсервисные вызовы выполнять по mTLS (service identity, cert pinning, trust policy), не только token exchange endpoint.

### AK-019 — ASVS L3 Admin Session: отсутствует ротация секретов и ограничение админ-сессий

- Source: `core/skills/auth-keycloak/patterns.md`
- Safe-Pattern: Для админ-учетных записей принудительная ротация клиентских секретов, короткий TTL сессий, step-up auth и немедленный revoke при logout/risk events.

### APP-100 — Duplicate token issuance in parallel flow

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Вводить idempotency-key и single-flight для token issue.

### APP-101 — Missing client timeout policy

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Обязательный timeout + retry budget + circuit breaker.

### APP-102 — Fail-open fallback on auth provider error

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Fail-closed при ошибке внешнего IdP.

### APP-103 — Missing token replay binding

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Привязка токена к nonce/device/session fingerprint.

### APP-104 — Missing MFA enforcement on critical action

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Обязательный MFA gate для high-risk операций.

### APP-105 — Admin action without re-auth

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Re-auth/step-up перед привилегированными операциями.

### APP-106 — Broad role wildcard in policy

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Явный least-privilege allowlist ролей.

### APP-107 — Static service token reuse

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Scope-bound short-lived tokens per service.

### APP-108 — Missing session revocation propagation

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Central revocation + backchannel logout.

### APP-109 — Privileged action via GET

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Использовать POST/PUT/PATCH + CSRF guards.

### APP-110 — Missing authz check in background worker

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Проверять subject/scope до исполнения job.

### APP-111 — Weak API key rotation policy

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Ротация по SLA + автоотзыв компрометированных ключей.

### APP-112 — No lockout on auth brute force

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Rate-limit + progressive delay + lockout.

### APP-113 — No tenant isolation in access token

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Включать tenant claim + enforce в policy layer.

### APP-114 — Missing auth audit trail

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Централизованный security audit log.

### APP-115 — Insecure impersonation flow

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Signed delegation token + bounded TTL + audit.

### APP-116 — Silent token refresh failures

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Явная обработка ошибок + forced re-auth.

### APP-117 — No anti-automation controls on auth APIs

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Risk-based controls, captcha/behavioral checks.

### APP-118 — Missing consent boundary for delegated scopes

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Явный consent prompt + least-scope default.

### APP-119 — Auth cache poisoning risk

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Cache key по subject+scope+tenant+ttl.

### BIZ-001 — BOLA: доступ к объекту по `id` без ownership check

- Source: `core/skills/app-logic/patterns.md`
- Safe-Pattern: `@app.get("/orders/{order_id}")`<br>`async def get_order(order_id: int, user=Depends(current_user)):`<br>`    order = await repo.get_order(order_id)`<br>`    if not order or order.owner_id != user.id:`<br>`        raise HTTPException(status_code=404, detail="not found")`<br>`    return order`

### BIZ-002 — BOLA: доверие `user_id` из query/body

- Source: `core/skills/app-logic/patterns.md`
- Safe-Pattern: `@app.get("/profile")`<br>`async def profile(user=Depends(current_user)):`<br>`    return await repo.get_profile(user.id)`

### BIZ-003 — BOPLA: массовое обновление защищенных полей

- Source: `core/skills/app-logic/patterns.md`
- Safe-Pattern: `class AccountUpdatePublic(BaseModel):`<br>`    email: EmailStr

### BIZ-004 — Vertical privilege escalation через `role` из клиентского payload

- Source: `core/skills/app-logic/patterns.md`
- Safe-Pattern: `@app.post("/admin/promote")`<br>`async def promote(dto: PromoteUserDTO, actor=Depends(current_user)):`<br>`    if actor.role != "admin":`<br>`        raise HTTPException(status_code=403, detail="forbidden")`<br>`    if dto.role not in {"manager", "auditor"}:`<br>`        raise HTTPException(status_code=400, detail="invalid role")`<br>`    await repo.update_user(dto.user_id, role=dto.role)`

### BIZ-005 — MFA bypass: высокорисковая операция без step-up статуса

- Source: `core/skills/app-logic/patterns.md`
- Safe-Pattern: `@app.post("/payments/{payment_id}/confirm")`<br>`async def confirm(payment_id: int, user=Depends(current_user)):`<br>`    if not user.step_up_verified_at or user.step_up_verified_at < datetime.now(timezone.utc) - timedelta(minutes=5):`<br>`        raise HTTPException(status_code=401, detail="step-up required")`<br>`    return await payments.confirm(payment_id, user.id)`

### BIZ-006 — Missing transaction binding: подтверждение операции не связано с challenge

- Source: `core/skills/app-logic/patterns.md`
- Safe-Pattern: `@app.post("/mfa/verify")`<br>`async def verify(req: MFAVerifyRequest, user=Depends(current_user)):`<br>`    challenge = await mfa.get_challenge(req.challenge_id)`<br>`    if not challenge or challenge.user_id != user.id or challenge.context != req.context:`<br>`        raise HTTPException(status_code=400, detail="invalid challenge")`<br>`    if not await mfa.verify_code(user.id, req.code):`<br>`        raise HTTPException(status_code=401, detail="invalid code")`<br>`    await mfa.mark_step_up(user.id, context=req.context)`<br>`    return {"ok": True}`

### BIZ-007 — Broken workflow: пропуск обязательного шага (draft->paid напрямую)

- Source: `core/skills/app-logic/patterns.md`
- Safe-Pattern: `ALLOWED = {"draft": {"submitted"}, "submitted": {"approved"}, "approved": {"paid"}}`<br>`@app.post("/orders/{order_id}/pay")`<br>`async def pay(order_id: int, user=Depends(current_user)):`<br>`    order = await repo.get_order(order_id)`<br>`    if not order or order.owner_id != user.id:`<br>`        raise HTTPException(status_code=404, detail="not found")`<br>`    if "paid" not in ALLOWED.get(order.status, set()):`<br>`        raise HTTPException(status_code=409, detail="invalid transition")`<br>`    await repo.update_order(order_id, status="paid")`

### BIZ-008 — Replay на критический endpoint без idempotency key

- Source: `core/skills/app-logic/patterns.md`
- Safe-Pattern: `@app.post("/transfers")`<br>`async def transfer(req: TransferRequest, request: Request, user=Depends(current_user)):`<br>`    idem = request.headers.get("Idempotency-Key", "").strip()`<br>`    if not idem:`<br>`        raise HTTPException(status_code=400, detail="missing idempotency key")`<br>`    if await idem_store.exists(user.id, idem):`<br>`        raise HTTPException(status_code=409, detail="duplicate request")`<br>`    result = await svc.transfer(user.id, req.target_id, req.amount)`<br>`    await idem_store.save(user.id, idem)`<br>`    return result`

### BIZ-009 — Tenant breakout: отсутствие tenant-scope в выборке

- Source: `core/skills/app-logic/patterns.md`
- Safe-Pattern: `@app.get("/invoices/{invoice_id}")`<br>`async def invoice(invoice_id: int, user=Depends(current_user)):`<br>`    inv = await repo.get_invoice(invoice_id)`<br>`    if not inv or inv.tenant_id != user.tenant_id:`<br>`        raise HTTPException(status_code=404, detail="not found")`<br>`    return inv`

### BIZ-010 — Sensitive action без re-auth при long-lived session

- Source: `core/skills/app-logic/patterns.md`
- Safe-Pattern: `@app.post("/users/me/change-email")`<br>`async def change_email(req: ChangeEmailRequest, user=Depends(current_user)):`<br>`    if not await auth.verify_password(user.id, req.current_password):`<br>`        raise HTTPException(status_code=401, detail="re-auth required")`<br>`    await repo.update_user(user.id, email=req.new_email)`

### BIZ-011 — Business SSRF: сетевой вызов с необработанным пользовательским URL

- Source: `core/skills/app-logic/patterns.md`
- Safe-Pattern: `def _is_blocked_host(host: str) -> bool:`<br>`    if host in {"localhost"}:`<br>`        return True`<br>`    try:`<br>`        ip = ipaddress.ip_address(host)`<br>`        return ip.is_private or ip.is_loopback or ip.is_link_local`<br>`    except ValueError:`<br>`        return False`<br>`@app.post("/preview")`<br>`async def preview(dto: PreviewRequest):`<br>`    parsed = urlparse(dto.url)`<br>`    if parsed.scheme not in {"https"} or not parsed.hostname or _is_blocked_host(parsed.hostname):`<br>`        raise HTTPException(status_code=400, detail="blocked target")`<br>`    async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:`<br>`        r = await client.get(dto.url)`<br>`    return {"status": r.status_code}`

### BIZ-012 — Insecure Internal Trust: слепое доверие данным внутреннего сервиса

- Source: `core/skills/app-logic/patterns.md`
- Safe-Pattern: `class RiskResponse(BaseModel):`<br>`    user_id: int`<br>`    risk_level: Literal["low", "medium", "high"]`<br>`    allow_transfer: bool`<br>`@app.get("/risk/{user_id}")`<br>`async def risk(user_id: int):`<br>`    async with httpx.AsyncClient(timeout=5.0) as client:`<br>`        r = await client.get(f"http://risk.internal/score/{user_id}")`<br>`    r.raise_for_status()`<br>`    data = RiskResponse.model_validate(r.json())`<br>`    if data.user_id != user_id:`<br>`        raise HTTPException(status_code=502, detail="upstream mismatch")`<br>`    return {"allow_transfer": data.allow_transfer}`

### BIZ-013 — Shadow API Exposure: debug/legacy endpoint активен в prod

- Source: `core/skills/app-logic/patterns.md`
- Safe-Pattern: `def create_app(env: str) -> FastAPI:`<br>`    app = FastAPI()`<br>`    if env != "prod":`<br>`        @app.get("/debug/sql")`<br>`        async def debug_sql():`<br>`            return {"ok": True}`<br>`    return app`<br>`@app.get("/legacy/report", include_in_schema=False)`<br>`async def legacy_report():`<br>`    raise HTTPException(status_code=410, detail="endpoint removed")`

### BIZ-014 — Non-Atomic Financial Operations: неатомарное обновление баланса

- Source: `core/skills/app-logic/patterns.md`
- Safe-Pattern: `@app.post("/wallet/transfer")`<br>`async def transfer(req: TransferRequest, db=Depends(get_db)):`<br>`    async with db.transaction():`<br>`        src = await repo.get_wallet_for_update(req.src_id, db)`<br>`        dst = await repo.get_wallet_for_update(req.dst_id, db)`<br>`        if src.balance < req.amount:`<br>`            raise HTTPException(status_code=409, detail="insufficient funds")`<br>`        await repo.update_balance(req.src_id, -req.amount, db)`<br>`        await repo.update_balance(req.dst_id, req.amount, db)`

### BIZ-015 — Parameter Pollution (HPP): дубли query-параметров влияют на логику

- Source: `core/skills/app-logic/patterns.md`
- Safe-Pattern: `@app.get("/search")`<br>`async def search(request: Request):`<br>`    roles = request.query_params.getlist("role")`<br>`    if len(roles) != 1:`<br>`        raise HTTPException(status_code=400, detail="duplicate role parameter")`<br>`    role = roles[0]`<br>`    if role not in {"user", "manager"}:`<br>`        raise HTTPException(status_code=400, detail="invalid role")`<br>`    return await repo.search(role=role)`

### BIZ-016 — Unrestricted Export Size: экспорт без лимита количества записей

- Source: `core/skills/app-logic/patterns.md`
- Safe-Pattern: `MAX_EXPORT_ROWS = 10000`<br>`@app.get("/exports/orders.csv")`<br>`async def export_orders(limit: int = 1000):`<br>`    if limit <= 0 or limit > MAX_EXPORT_ROWS:`<br>`        raise HTTPException(status_code=400, detail="limit out of range")`<br>`    rows = await repo.list_orders(limit=limit)`<br>`    return to_csv(rows)`

### BIZ-017 — CSV/Excel Formula Injection: спецсимволы не нейтрализуются при экспорте

- Source: `core/skills/app-logic/patterns.md`
- Safe-Pattern: `DANGEROUS_PREFIXES = ("=", "+", "-", "@")`<br>`def sanitize_cell(value: str) -> str:`<br>`    if value.startswith(DANGEROUS_PREFIXES):`<br>`        return "'" + value`<br>`    return value`<br>`def row_to_csv(user: dict[str, str]) -> list[str]:`<br>`    return [`<br>`        sanitize_cell(user["name"]),`<br>`        sanitize_cell(user["email"]),`<br>`        sanitize_cell(user["comment"]),`<br>`    ]`

### BIZ-018 — Trusting Client-Side Calculations: сервер принимает цену/скидку от клиента

- Source: `core/skills/app-logic/patterns.md`
- Safe-Pattern: `@app.post("/checkout")`<br>`async def checkout(req: CheckoutRequest, user=Depends(current_user)):`<br>`    items = await catalog.get_items(req.item_ids)`<br>`    subtotal = sum(item.price for item in items)`<br>`    discount = await promotions.calculate_discount(user.id, req.promo_code, items)`<br>`    total = max(subtotal - discount, 0)`<br>`    if req.client_total is not None and abs(req.client_total - total) > Decimal("0.01"):`<br>`        raise HTTPException(status_code=400, detail="price tampering detected")`<br>`    await billing.charge(user.id, total)`

### BIZ-019 — Webhook Signature Verification Missing: внешние callback-и принимаются без подписи

- Source: `core/skills/app-logic/patterns.md`
- Safe-Pattern: `@app.post("/webhook/payment")`<br>`async def payment_webhook(request: Request):`<br>`    body = await request.body()`<br>`    sig = request.headers.get("x-signature", "")`<br>`    if not verify_hmac(body, sig, webhook_secret):`<br>`        raise HTTPException(status_code=401, detail="invalid signature")`<br>`    payload = json.loads(body)`<br>`    ...`<br>`    await payments.mark_paid(payload["order_id"])`

### BRW-001 — Playwright: запуск без sandbox (`--no-sandbox`)

- Source: `core/skills/browser-agent/patterns.md`
- Safe-Pattern: `browser = await p.chromium.launch(`<br>`  args=[],`<br>`  headless=True,`<br>`)`

### BRW-002 — Playwright: `ignoreHTTPSErrors=True`

- Source: `core/skills/browser-agent/patterns.md`
- Safe-Pattern: `context = await browser.new_context(ignoreHTTPSErrors=False)`<br>`page = await context.new_page()`

### BRW-003 — Prod: `headless: false`

- Source: `core/skills/browser-agent/patterns.md`
- Safe-Pattern: `browser = await p.chromium.launch(headless=True)`

### BRW-004 — WebRTC metadata leakage через page.evaluate()

- Source: `core/skills/browser-agent/patterns.md`
- Safe-Pattern: `await page.route(\"**/*\", lambda route: route.abort() if \"stun\" in route.request.url else route.continue_())`

### BRW-005 — Пользовательский JS через page.evaluate()

- Source: `core/skills/browser-agent/patterns.md`
- Safe-Pattern: `allowed = {\"scrollToTop\",\"extractText\"}`<br>`cmd = request.json()[\"cmd\"]`<br>`if cmd not in allowed: raise ValueError(\"cmd rejected\")`<br>`await page.evaluate(\"(arg) => window.scrollTo(0,0)\", None)`

### BRW-006 — Отключение защитных флагов Chromium

- Source: `core/skills/browser-agent/patterns.md`
- Safe-Pattern: `browser = await p.chromium.launch(args=[])`

### BRW-007 — File Protocol Restriction: `file://` разрешен в `page.goto()`

- Source: `core/skills/browser-agent/patterns.md`
- Safe-Pattern: `target = user_input_url`<br>`if target.startswith(\"file://\"):`<br>`    raise ValueError(\"file protocol is forbidden\")`<br>`await page.goto(target, wait_until=\"domcontentloaded\")`

### BRW-008 — SSRF via Browser: доступ к localhost/metadata endpoints

- Source: `core/skills/browser-agent/patterns.md`
- Safe-Pattern: `import ipaddress`<br>`from urllib.parse import urlparse`<br><br>`def _blocked_host(host: str) -> bool:`<br>`    if host in {\"localhost\"}:`<br>`        return True`<br>`    try:`<br>`        ip = ipaddress.ip_address(host)`<br>`        return ip.is_loopback or ip.is_private or ip.is_link_local`<br>`    except ValueError:`<br>`        return False`<br><br>`parsed = urlparse(url)`<br>`if _blocked_host(parsed.hostname or \"\") or (parsed.hostname == \"169.254.169.254\"):`<br>`    raise ValueError(\"blocked destination\")`<br>`await page.goto(url, wait_until=\"domcontentloaded\")`

### BRW-009 — Zombies & Leaks: контекст не закрывается, timeout не задан

- Source: `core/skills/browser-agent/patterns.md`
- Safe-Pattern: `context = await browser.new_context()`<br>`try:`<br>`    page = await context.new_page()`<br>`    page.set_default_navigation_timeout(10000)`<br>`    await page.goto(url, timeout=10000, wait_until=\"domcontentloaded\")`<br>`finally:`<br>`    await context.close()`

### BRW-010 — Download Restrictions: автоскачивание включено, MIME не проверяется

- Source: `core/skills/browser-agent/patterns.md`
- Safe-Pattern: `context = await browser.new_context(accept_downloads=False)`<br>`page = await context.new_page()`<br>`resp = await page.goto(url, wait_until=\"domcontentloaded\")`<br>`content_type = (resp.headers.get(\"content-type\", \"\") if resp else \"\")`<br>`allowed = {\"text/html\", \"application/json\"}`<br>`if content_type.split(\";\")[0] not in allowed:`<br>`    raise ValueError(\"blocked MIME type\")`

### BRW-011 — DOM XSS: пользовательский контент вставляется через `innerHTML`

- Source: `core/skills/browser-agent/patterns.md`
- Safe-Pattern: `const note = request.body.note`<br>`...`<br>`await page.evaluate((value) => { document.querySelector("#out").textContent = value }, note)`

### BRW-012 — JS Injection: выполнение пользовательского JS через `eval`/`new Function`

- Source: `core/skills/browser-agent/patterns.md`
- Safe-Pattern: `const cmd = request.body.cmd`<br>`allowed = {"scrollTop":"window.scrollTo(0,0)"}`<br>`if (!(cmd in allowed)) throw new Error("cmd rejected")`<br>`...`<br>`await page.evaluate(allowed[cmd])`

### BRW-013 — Prototype Pollution: запись в `__proto__` / merge без фильтра ключей

- Source: `core/skills/browser-agent/patterns.md`
- Safe-Pattern: `const patch = request.body.patch`<br>`for (const k of Object.keys(patch)) {`<br>`  if (["__proto__","constructor","prototype"].includes(k)) throw new Error("blocked key")`<br>`}`<br>`...`<br>`Object.assign(config, patch)`

### CSH-001 — C# Code Injection: `CSharpScript.EvaluateAsync` на пользовательском вводе

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: `var expr = request.Query["expr"];`<br>`if (!Regex.IsMatch(expr, "^[0-9+\\-*/(). ]{1,64}$")) throw new Exception("invalid");`<br>`...`<br>`var result = SafeMath.Eval(expr);`

### CSH-002 — Command Injection: `Process.Start` со строкой аргументов

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: `var host = request.Query["host"];`<br>`if (!Regex.IsMatch(host, "^[a-zA-Z0-9.-]{1,255}$")) throw new Exception("invalid");`<br>`...`<br>`Process.Start(new ProcessStartInfo { FileName = "ping", ArgumentList = { host }, UseShellExecute = false });`

### CSH-003 — Shell Execute Injection: `UseShellExecute=true` с пользовательским вводом

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: `var action = request.Query["action"];`<br>`var allowed = new Dictionary<string,string[]> { ["uptime"] = new[] { "uptime" } };`<br>`...`<br>`Process.Start(new ProcessStartInfo { FileName = allowed[action][0], UseShellExecute = false });`

### CSH-004 — Unsafe Reflection: `Type.GetType` из user input

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: `var key = request.Query["handler"];`<br>`var allowed = new Dictionary<string, Type> { ["health"] = typeof(HealthHandler) };`<br>`...`<br>`var t = allowed[key];`

### CSH-005 — Dynamic Invoke Injection: `GetMethod(...).Invoke` без allowlist

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: `var method = request.Query["method"];`<br>`if (!new[] { "Health", "Status" }.Contains(method)) throw new Exception("blocked");`<br>`...`<br>`target.GetType().GetMethod(method).Invoke(target, null);`

### CSH-006 — SQL Fragment Injection в `ORDER BY`

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: `var order = request.Query["order"];`<br>`if (!new[] { "name", "created_at" }.Contains(order)) order = "name";`<br>`...`<br>`var sql = $"SELECT * FROM users ORDER BY {order}";`

### CSH-007 — Roslyn Compilation of Untrusted Code

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: `var code = request.Form["code"];`<br>`throw new SecurityException("runtime compilation disabled");`

### CSH-008 — JavaScript Engine Injection (Jint/ClearScript)

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: `var cmd = request.Form["cmd"];`<br>`if (!new[] { "normalize" }.Contains(cmd)) throw new SecurityException();`<br>`...`<br>`engine.Invoke("normalize", value);`

### CSH-009 — Небезопасная десериализация

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: `...`<br>`JsonSerializer.Deserialize<T>(json);`<br>`...`<br>`new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None }`

### CSH-010 — XXE Injection

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: `var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibited };`<br>`...`<br>`var reader = XmlReader.Create(stream, settings);`

### CSH-011 — Insecure Cookie Flags

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: `var opts = new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict };`<br>`...`<br>`Response.Cookies.Append("session", token, opts);`

### CSH-012 — Hardcoded Secrets

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: `var defaultConnection = builder.Configuration["ConnectionStrings:Default"] ?? throw new InvalidOperationException();`<br>`...`<br>`var apiKey = Environment.GetEnvironmentVariable("API_KEY") ?? throw new InvalidOperationException();`

### CSH-013 — Weak Crypto

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: `...`<br>`using (var sha512 = SHA512.Create())`<br>`...`<br>`Argon2id.HashPassword(password, salt)`

### CSH-014 — Open Redirect

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: `var url = Request.Query["redirect"];`<br>`if (!Url.IsLocalUrl(url)) throw new Exception("blocked");`<br>`...`<br>`return LocalRedirect(url);`

### CSH-015 — Certificate Validation Bypass

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: `var handler = new HttpClientHandler();`<br>`...`<br>`handler.ServerCertificateCustomValidationCallback = ValidateServerCertificate;`

### CSH-016 — Weak Password Hashing

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: `...`<br>`BCrypt.Net.BCrypt.HashPassword(password)`<br>`...`<br>`Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA512, 32)`

### CSH-017 — Office HTML Injection в Outlook/Excel формулы

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: Санитизировать HTML и экранировать Excel formula input (префикс `'`), применять allowlist шаблонов контента.

### CSH-018 — VSTO macro-equivalent command execution

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: Запретить запуск макросов/команд из пользовательского ввода, использовать allowlist команд и подписи.

### CSH-019 — Banned BinaryFormatter Deserialize

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: Полностью исключить `BinaryFormatter`, использовать безопасные сериализаторы и типизированные DTO.

### CSH-020 — Insecure DataSet.ReadXml from untrusted input

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: Валидировать XML schema, отключить DTD/XXE и использовать безопасный parser pipeline.

### CSH-021 — Unsafe P/Invoke marshaling

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: Указывать `BestFitMapping=false`, `CharSet.Unicode`, проверять границы строковых параметров и pinvoke allowlist.

### CSH-022 — Insecure Assembly.Load from path/user input

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: Загружать только подписанные/доверенные assembly из allowlist директорий с проверкой strong name.

### CSH-023 — ASP.NET Mass Assignment (Entity binding)

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: Принимать DTO/ViewModel, whitelist полей и map вручную в entity.

### CSH-024 — Unsafe AutoMapper profile exposing privileged fields

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: Явно ignore privileged fields (`IsAdmin`, `Role`, `Balance`) и использовать explicit mapping policy.

### CSH-025 — JWT validation gaps in .NET auth

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: Включить `ValidateIssuer=true`, `ValidateAudience=true`, настроить valid issuers/audiences и lifetime checks.

### CSH-026 — OAuth redirect URI not validated

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: Использовать strict allowlist redirect URI и local-url checks.

### CSH-027 — Insecure file upload without extension/content checks

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: Проверять extension + MIME + magic bytes, сохранять вне webroot и randomize file name.

### CSH-028 — Path traversal in static file/document download

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: Нормализовать путь, проверять boundary и deny traversal sequences.

### CSH-029 — Missing anti-forgery on state-changing MVC actions

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: Включить `ValidateAntiForgeryToken` и CSRF middleware для cookie-auth flows.

### CSH-030 — Insecure session config in .NET 4.8

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: Включить secure/httpOnly/sameSite и idle timeout policy.

### CSH-031 — Json.NET TypeNameHandling unsafe mode

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: Использовать `TypeNameHandling.None`, custom binder allowlist и DTO-only deserialization.

### CSH-032 — ASP.NET request validation disabled

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: Не отключать request validation; использовать safe HTML sanitizer pipeline.

### CSH-033 — Weak TLS protocol negotiation

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: Tls`

### CSH-034 — Insecure random via System.Random for secrets

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: Использовать `RandomNumberGenerator.GetBytes` для security values.

### CSH-035 — Sensitive data in logs/debug output

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: Маскировать/редактировать чувствительные поля и запретить plaintext credentials в логах.

### CSH-036 — LDAP injection via unescaped filter

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: Экранировать LDAP filter chars и использовать parameterized/escaped filter builders.

### CSH-037 — Regex DoS in server validation

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: Ограничивать input length, timeout regex engine и избегать catastrophic patterns.

### CSH-038 — XML signature validation bypass

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: Проверять подпись, certificate chain, reference URI и canonicalization constraints.

### CSH-039 — gRPC auth metadata not validated

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: Проверять JWT/claims server-side и не доверять client-provided role headers.

### CSH-040 — GraphQL over-posting of sensitive fields

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: Ограничивать schema, field-level authz и query depth/complexity limits.

### CSH-041 — Entity Framework FromSqlRaw injection

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: Использовать `FromSqlInterpolated`/parameters и запрет raw concat.

### CSH-042 — Open telemetry export without data scrubbing

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: Включать scrubbing policy и denylist sensitive attributes before export.

### CSH-043 — WebClient legacy insecure usage

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: Переходить на `HttpClient` с timeout/TLS validation/policies.

### CSH-044 — Hardcoded service account credentials

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: Использовать managed identity/secret manager и ротацию учетных данных.

### CSH-045 — Missing object-level authorization in API

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: Проверять владение/доступ per object before returning/modifying entity.

### CSH-046 — Unsafe cleanup deletion with user-supplied path

- Source: `core/skills/csharp-dotnet/patterns.md`
- Safe-Pattern: Нормализовать path, проверять allowed directory и deny traversal before deletion.

### DJA-001 — CSRF Disabled: view без CSRF-защиты

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: `@csrf_protect`<br>`def update_profile(request):`<br>`    ...`<br>`    return JsonResponse({"ok": True})`

### DJA-002 — Raw SQL Injection: строковая конкатенация в SQL

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: `q = "SELECT * FROM users WHERE email = %s"`<br>`...`<br>`User.objects.raw(q, [email])`

### DJA-003 — DEBUG=True in Production

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: `DEBUG = os.getenv("DJANGO_DEBUG", "false").lower() == "true"`

### DJA-004 — Mass Assignment: `ModelForm` без явных `fields`

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: `class UserForm(forms.ModelForm):`<br>`    class Meta:`<br>`        model = User`<br>`        fields = ["email", "display_name"]`

### DJA-005 — Insecure ALLOWED_HOSTS wildcard

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: `ALLOWED_HOSTS = ["app.example.com", "admin.example.com"]`

### DJA-006 — Open Redirect через `next` без проверки

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: `next_url = request.GET.get("next", "/")`<br>`if not url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):`<br>`    next_url = "/"`<br>`return redirect(next_url)`

### DJA-007 — Insecure Cookie Flags (SESSION/CSRF)

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: `SESSION_COOKIE_SECURE = True`<br>`SESSION_COOKIE_HTTPONLY = True`<br>`CSRF_COOKIE_SECURE = True`

### DJA-008 — Hardcoded Secret Key

- Source: `core/skills/domain-data-privacy/patterns.md`
- Safe-Pattern: `SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]`

### DJA-009 — Unsafe file upload path (path traversal)

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: `safe_name = os.path.basename(upload.name)`<br>`path = os.path.join("/data/uploads", safe_name)`<br>`...`<br>`with open(path, "wb") as f:`

### DJA-010 — Verbose error leakage to client

- Source: `core/skills/domain-data-privacy/patterns.md`
- Safe-Pattern: `try:`<br>`    ...`<br>`except Exception:`<br>`    logger.exception("internal error")`<br>`    return JsonResponse({"error": "internal server error"}, status=500)`

### DJA-011 — XSS via `mark_safe`: доверие пользовательскому HTML

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: `html = format_html("{}", user_input)`<br>`...`<br>`html = bleach.clean(user_input)`

### DJA-012 — Unsafe Session Serializer: `PickleSerializer`

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: `SESSION_SERIALIZER = "django.contrib.sessions.serializers.JSONSerializer"`

### DJA-013 — Insecure `.extra()` where clause

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: `qs = User.objects.filter(id=user_id)`

### DJA-014 — Weak password hasher

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: `PASSWORD_HASHERS = ["django.contrib.auth.hashers.Argon2PasswordHasher", "django.contrib.auth.hashers.BCryptSHA256PasswordHasher"]`

### DJA-015 — Unsafe logout redirect

- Source: `core/skills/domain-data-privacy/patterns.md`
- Safe-Pattern: `LOGOUT_REDIRECT_URL = "/accounts/login/"`<br>`...`<br>`safe_next = url_has_allowed_host_and_scheme(next_url, allowed_hosts={host})`

### DJA-016 — ReDoS in URL patterns via complex `re_path`

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: `urlpatterns = [`<br>`    path("items/<slug:item>/", view),`<br>`]`

### DJA-017 — ModelForm `exclude=[]` abuse

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: `class AdminForm(forms.ModelForm):`<br>`    class Meta:`<br>`        model = User`<br>`        fields = ["email", "display_name"]`

### DJA-018 — Missing `LoginRequiredMixin` on CBV

- Source: `core/skills/domain-data-privacy/patterns.md`
- Safe-Pattern: `class PaymentsView(LoginRequiredMixin, View):`<br>`    def dispatch(self, request, *args, **kwargs):`<br>`        ...`

### DOCK-010 — Container runs as root

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `RUN adduser -D appuser`<br>`USER appuser`

### DOCK-011 — Missing non-root USER in final stage

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `FROM alpine:3.20`<br>`USER 10001`<br>`CMD ["app"]`

### DOCK-012 — Writable root filesystem by default

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `docker run --read-only --tmpfs /tmp app@sha256:...`

### DOCK-013 — Base image uses latest tag

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `FROM node:20.11.1@sha256:...`

### DOCK-014 — ADD used for remote URL

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `COPY app.tar.gz /opt/`

### DOCK-015 — Package manager cache not cleaned

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*`

### DOCK-016 — Sensitive values in ENV/ARG

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `ARG API_TOKEN`<br>`# inject via runtime secrets`

### DOCK-017 — No HEALTHCHECK instruction

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `HEALTHCHECK CMD curl -f http://localhost:8080/health

### DOCK-018 — Privileged container run flags

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `docker run --cap-drop ALL --security-opt no-new-privileges app:1.0`

### DOCK-019 — Docker socket mounted into container

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `# do not mount docker.sock`

### DOCK-020 — No seccomp profile at runtime

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `docker run --security-opt seccomp=default.json app:1.0`

### DSK-100 — Electron remote code injection path

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Запрет string-exec, передача данных через безопасный IPC.

### DSK-105 — Insecure IPC for sensitive actions

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Использовать `ipcMain.handle` + schema validation + authz.

### DSK-110 — Old xlsx prototype pollution risk

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Обновление зависимости + hardening bootstrap.

### DVS-001 — Dockerfile: Запуск от root (USER root / отсутствие USER)

- Source: `core/skills/devops-security/patterns.md`
- Safe-Pattern: Создать непривилегированного пользователя (`useradd -m appuser`) и запускать контейнер через `USER appuser`.

### DVS-002 — Dockerfile: Теги latest в базовых образах

- Source: `core/skills/devops-security/patterns.md`
- Safe-Pattern: Фиксировать образ по версии/диджесту (`FROM node:20.12.2`, `FROM alpine@sha256:...`).

### DVS-003 — Dockerfile: Секреты в ENV/ARG

- Source: `core/skills/devops-security/patterns.md`
- Safe-Pattern: Использовать runtime secret injection (Vault/ESO/K8s Secret), исключить секреты из Docker build layers.

### DVS-004 — SLSA L1/L2: отсутствует provenance-аттестация сборки

- Source: `core/skills/devops-security/patterns.md`
- Safe-Pattern: Генерировать provenance-аттестацию (builder, source, digest, timestamp, workflow id) и сохранять ее как обязательный артефакт релиза.

### DVS-005 — NIST SSDF: зависимости с известными CVE допускаются в релиз

- Source: `core/skills/devops-security/patterns.md`
- Safe-Pattern: Блокировать релиз при High/Critical CVE, учитывать результаты Syft/SCA в policy gate и сохранять решение в CI logs.

### DVS-006 — Hermetic Builds: внешние сетевые вызовы в build-стадии

- Source: `core/skills/devops-security/patterns.md`
- Safe-Pattern: sh`

### DVS-007 — VEX Filter: CVE не фильтруются по VEX-статусу `not_affected`

- Source: `core/skills/devops-security/patterns.md`
- Safe-Pattern: При policy-gate учитывать VEX-аттестации; CVE со статусом `not_affected` маркировать как исключение с audit trail.

### DVS-008 — Artifact Signing: release-образы публикуются без подписи

- Source: `core/skills/devops-security/patterns.md`
- Safe-Pattern: Обязательная подпись артефактов (например, cosign), валидация подписи при деплое и хранение attestations.

### DVS-009 — Reproducible Build: недетерминированные сборки без проверки повторяемости

- Source: `core/skills/devops-security/patterns.md`
- Safe-Pattern: Пинning base images/dependencies, deterministic flags и периодическая проверка reproducibility hash между сборками.

### FAS-001 — SlowAPI: неверный порядок декораторов `limit`

- Source: `core/skills/fastapi-async/patterns.md`
- Safe-Pattern: `@app.get("/test")`<br>`@limiter.limit("2/minute")`<br>`async def test(request: Request):`<br>`    return "hi"`

### FAS-002 — SlowAPI: endpoint без `request: Request`

- Source: `core/skills/fastapi-async/patterns.md`
- Safe-Pattern: `@app.get("/limited")`<br>`@limiter.limit("5/minute")`<br>`async def limited(request: Request) -> dict[str, str]:`<br>`    return {"status": "ok"}`

### FAS-003 — SlowAPI: нет `response` при необходимости модификации заголовков

- Source: `core/skills/fastapi-async/patterns.md`
- Safe-Pattern: `@app.get("/mars")`<br>`@limiter.limit("5/minute")`<br>`async def homepage(request: Request, response: Response) -> dict[str, str]:`<br>`    return {"key": "value"}`

### FAS-004 — SQLi: интерполяция значений в SQL (без `:param`)

- Source: `core/skills/fastapi-async/patterns.md`
- Safe-Pattern: `query = "INSERT INTO HighScores(name, score) VALUES (:name, :score)"`<br>`values = {"name": name, "score": score}`<br>`await database.execute(query=query, values=values)`

### FAS-005 — SQLi: конкатенация строк в SQL (без `:param`)

- Source: `core/skills/fastapi-async/patterns.md`
- Safe-Pattern: `query = "INSERT INTO HighScores(name, score) VALUES (:name, :score)"`<br>`values = {"name": name, "score": score}`<br>`await database.execute(query=query, values=values)`

### FAS-006 — Transaction Leak: несколько `execute()` без `async with database.transaction()`

- Source: `core/skills/fastapi-async/patterns.md`
- Safe-Pattern: `async with database.transaction(force_rollback=True):`<br>`    await database.execute(query=query1, values=values1)`<br>`    await database.execute(query=query2, values=values2)`

### FAS-007 — Missing `await` на async DB call

- Source: `core/skills/fastapi-async/patterns.md`
- Safe-Pattern: `await database.execute(query=query, values=values)`

### FAS-008 — Global Client Reuse: создание `AsyncClient`/DB-коннекта внутри хендлера

- Source: `core/skills/fastapi-async/patterns.md`
- Safe-Pattern: `app = FastAPI()`<br>`@app.on_event("startup")`<br>`async def startup() -> None:`<br>`    app.state.http = httpx.AsyncClient(timeout=5.0)`<br>`@app.on_event("shutdown")`<br>`async def shutdown() -> None:`<br>`    await app.state.http.aclose()`<br>`@app.get("/proxy")`<br>`async def proxy(url: str, request: Request):`<br>`    r = await request.app.state.http.get(url)`<br>`    return {"status": r.status_code}`

### FAS-009 — Missing Timeouts: асинхронные сетевые вызовы без `timeout`

- Source: `core/skills/fastapi-async/patterns.md`
- Safe-Pattern: `timeout = httpx.Timeout(connect=2.0, read=5.0, write=5.0, pool=2.0)`<br>`async with httpx.AsyncClient(timeout=timeout) as client:`<br>`    r = await client.get("https://api.example.internal/data", timeout=timeout)`

### FAS-010 — PII Leakage in Logs: логирование `Request`/секретных полей без маскирования

- Source: `core/skills/fastapi-async/patterns.md`
- Safe-Pattern: `def _mask(data: dict[str, object]) -> dict[str, object]:`<br>`    masked = dict(data)`<br>`    for key in ("password", "token", "access_token", "refresh_token", "email", "phone"):`<br>`        if key in masked:`<br>`            masked[key] = "***"`<br>`    return masked`<br>`@app.post("/login")`<br>`async def login(request: Request):`<br>`    body = await request.json()`<br>`    logger.info("request_id=%s payload=%s", request.headers.get("x-request-id", "-"), _mask(body))`<br>`    return {"ok": True}`

### FAS-011 — Exposed Docs in Prod: Swagger/ReDoc включены в production

- Source: `core/skills/fastapi-async/patterns.md`
- Safe-Pattern: `def create_app(env: str) -> FastAPI:`<br>`    is_prod = env == "prod"`<br>`    return FastAPI(` <br>`        title="HexVibe API",`<br>`        docs_url=None if is_prod else "/docs",`<br>`        redoc_url=None if is_prod else "/redoc",`<br>`        openapi_url=None if is_prod else "/openapi.json",`<br>`    )`

### FAS-012 — Insecure CORS Policy: `allow_origins=["*"]`

- Source: `core/skills/fastapi-async/patterns.md`
- Safe-Pattern: `allowed_origins = [`<br>`    "https://app.example.com",`<br>`    "https://admin.example.com",`<br>`]`<br>`app.add_middleware(` <br>`    CORSMiddleware,`<br>`    allow_origins=allowed_origins,`<br>`    allow_credentials=True,`<br>`    allow_methods=["GET", "POST", "PUT", "DELETE"],`<br>`    allow_headers=["Authorization", "Content-Type"],`<br>`)`

### FAS-013 — Pydantic Arbitrary Types: `arbitrary_types_allowed=True` в модели

- Source: `core/skills/fastapi-async/patterns.md`
- Safe-Pattern: `class UploadMeta(BaseModel):`<br>`    file_name: constr(min_length=1, max_length=255)`<br>`    size: conint(ge=1, le=10_000_000)`<br>`    content_type: Literal["image/png", "image/jpeg", "application/pdf"]`<br>`    model_config = ConfigDict(extra="forbid", strict=True)`

### FAS-014 — Background Task Exception Handling: задача без `try/except`

- Source: `core/skills/fastapi-async/patterns.md`
- Safe-Pattern: `def send_email_task(email: str, payload: dict[str, object]) -> None:`<br>`    try:`<br>`        smtp_client.send(email, payload)`<br>`    except Exception as exc:`<br>`        logger.exception("background task failed: %s", exc)`<br>`@app.post("/notify")`<br>`async def notify(background_tasks: BackgroundTasks):`<br>`    background_tasks.add_task(send_email_task, "user@example.com", {"status": "ok"})`<br>`    return {"queued": True}`

### FAS-015 — Large Payload DoS: upload endpoint без лимита размера тела

- Source: `core/skills/fastapi-async/patterns.md`
- Safe-Pattern: `MAX_BYTES = 5 * 1024 * 1024`<br>`@app.post("/upload")`<br>`async def upload(request: Request, file: UploadFile):`<br>`    content_length = int(request.headers.get("content-length", "0"))`<br>`    if content_length <= 0 or content_length > MAX_BYTES:`<br>`        raise HTTPException(status_code=413, detail="payload too large")`<br>`    data = await file.read(MAX_BYTES + 1)`<br>`    if len(data) > MAX_BYTES:`<br>`        raise HTTPException(status_code=413, detail="payload too large")`<br>`    return {"size": len(data)}`

### FAS-016 — Host/Header Injection: отсутствие валидации `Host` и `X-` заголовков

- Source: `core/skills/fastapi-async/patterns.md`
- Safe-Pattern: `ALLOWED_HOSTS = {"api.example.com", "admin.example.com"}`<br>`TENANT_RE = re.compile(r"^[a-z0-9-]{1,32}$")`<br>`@app.get("/tenant")`<br>`async def tenant_route(request: Request):`<br>`    host = request.headers.get("host", "").split(":")[0].lower()`<br>`    tenant = request.headers.get("x-tenant-id", "").strip().lower()`<br>`    if host not in ALLOWED_HOSTS:`<br>`        raise HTTPException(status_code=400, detail="invalid host")`<br>`    if not TENANT_RE.fullmatch(tenant):`<br>`        raise HTTPException(status_code=400, detail="invalid tenant header")`<br>`    callback = f"https://{host}/cb/{tenant}"`<br>`    return {"callback": callback}`

### FAS-017 — Mass Assignment Protection: прямой маппинг DTO в DB-модель

- Source: `core/skills/fastapi-async/patterns.md`
- Safe-Pattern: `class UserUpdateDTO(BaseModel):`<br>`    email: EmailStr

### FAS-018 — Insecure File Uploads: нет защиты от path traversal и magic-bytes проверки

- Source: `core/skills/fastapi-async/patterns.md`
- Safe-Pattern: `UPLOAD_DIR = Path("/data/uploads").resolve()`<br>`ALLOWED_MAGIC = {`<br>`    b"\\x89PNG\\r\\n\\x1a\\n": ".png",`<br>`    b"\\xff\\xd8\\xff": ".jpg",`<br>`    b"%PDF-": ".pdf",`<br>`}`<br>`@app.post("/files")`<br>`async def upload(file: UploadFile):`<br>`    safe_name = Path(file.filename or "upload.bin").name`<br>`    target = (UPLOAD_DIR / safe_name).resolve()`<br>`    if not str(target).startswith(str(UPLOAD_DIR)):`<br>`        raise HTTPException(status_code=400, detail="invalid path")`<br>`    data = await file.read(5 * 1024 * 1024 + 1)`<br>`    magic_ok = any(data.startswith(sig) for sig in ALLOWED_MAGIC)`<br>`    if not magic_ok:`<br>`        raise HTTPException(status_code=415, detail="unsupported file type")`<br>`    with target.open("wb") as out:`<br>`        out.write(data)`<br>`    return {"file": safe_name}`

### FAS-019 — Verbose Error Messages: возврат raw Exception в HTTP-ответ

- Source: `core/skills/fastapi-async/patterns.md`
- Safe-Pattern: `@app.get("/orders/{order_id}")`<br>`async def get_order(order_id: int):`<br>`    try:`<br>`        return await service.fetch(order_id)`<br>`    except DomainNotFoundError:`<br>`        raise HTTPException(status_code=404, detail="order not found")`<br>`    except Exception:`<br>`        logger.exception("unexpected error in get_order")`<br>`        raise HTTPException(status_code=500, detail="internal server error")`

### FAS-020 — Async Context Leakage: dependency без `yield/finally` не закрывает ресурсы

- Source: `core/skills/fastapi-async/patterns.md`
- Safe-Pattern: `async def get_db() -> AsyncGenerator[AsyncSession, None]:`<br>`    session = session_factory()`<br>`    try:`<br>`        yield session`<br>`    finally:`<br>`        await session.close()`<br>`@app.get("/users")`<br>`async def users(db: AsyncSession = Depends(get_db)):`<br>`    return await repo.list_users(db)`

### FAS-021 — OS Command Injection: shell-команда строится из пользовательского ввода

- Source: `core/skills/fastapi-async/patterns.md`
- Safe-Pattern: `HOST_RE = re.compile(r"^[a-zA-Z0-9.-]{1,255}$")`<br>`@app.get("/diag")`<br>`async def diag(host: str):`<br>`    if not HOST_RE.fullmatch(host):`<br>`        raise HTTPException(status_code=400, detail="invalid host")`<br>`    ...`<br>`    subprocess.run(["nslookup", host], shell=False, check=True)`

### FAS-022 — Unsafe Deserialization: `pickle.loads`/`yaml.load` на недоверенных данных

- Source: `core/skills/fastapi-async/patterns.md`
- Safe-Pattern: `class ImportDTO(BaseModel):`<br>`    kind: Literal["profile","settings"]`<br>`    data: dict[str, object]`<br>`@app.post("/import")`<br>`async def import_blob(dto: ImportDTO):`<br>`    ...`<br>`    validated = ImportDTO.model_validate(dto.model_dump())`

### FAS-023 — CSRF on Cookie Session: state-changing endpoint без CSRF-токена

- Source: `core/skills/fastapi-async/patterns.md`
- Safe-Pattern: `@app.post("/users/me/email")`<br>`async def change_email(req: dict, request: Request):`<br>`    csrf_cookie = request.cookies.get("csrf_token")`<br>`    csrf_header = request.headers.get("x-csrf-token")`<br>`    if not csrf_cookie or csrf_cookie != csrf_header:`<br>`        raise HTTPException(status_code=403, detail="csrf check failed")`<br>`    ...`<br>`    return await svc.change_email(request.cookies.get("session_id"), req["email"])`

### FAS-024 — SSTI: пользовательский шаблон рендерится на сервере

- Source: `core/skills/fastapi-async/patterns.md`
- Safe-Pattern: `SAFE_TEMPLATES = {"welcome.html", "invoice.html"}`<br>`@app.post("/render")`<br>`async def render(template_name: str, ctx: dict):`<br>`    if template_name not in SAFE_TEMPLATES:`<br>`        raise HTTPException(status_code=400, detail="template not allowed")`<br>`    ...`<br>`    return jinja_env.get_template(template_name).render(**ctx)`

### FAS-025 — Code Injection: выполнение пользовательского кода через `eval/exec`

- Source: `core/skills/fastapi-async/patterns.md`
- Safe-Pattern: `ALLOWED_EXPR = re.compile(r"^[0-9+\\-*/(). ]{1,128}$")`<br>`@app.post("/calc")`<br>`async def calc(user_input: str):`<br>`    if not ALLOWED_EXPR.fullmatch(user_input):`<br>`        raise HTTPException(status_code=400, detail="invalid expression")`<br>`    ...`<br>`    return {"result": safe_eval_math(user_input)}`

### FAS-026 — Command Injection: небезопасный shell-вызов через `os.system`/`subprocess(..., shell=True)`

- Source: `core/skills/fastapi-async/patterns.md`
- Safe-Pattern: `@app.post("/ops/run")`<br>`async def run(action: str):`<br>`    allowed = {"uptime": ["uptime"], "date": ["date"]}`<br>`    if action not in allowed:`<br>`        raise HTTPException(status_code=400, detail="action not allowed")`<br>`    ...`<br>`    subprocess.run(allowed[action], shell=False, check=True)`

### FAS-027 — Unsafe Imports: динамический `__import__` из пользовательского ввода

- Source: `core/skills/fastapi-async/patterns.md`
- Safe-Pattern: `SAFE_MODULES = {"json", "math"}`<br>`@app.get("/plugin")`<br>`async def plugin(mod: str):`<br>`    if mod not in SAFE_MODULES:`<br>`        raise HTTPException(status_code=400, detail="module not allowed")`<br>`    ...`<br>`    m = importlib.import_module(mod)`

### FTS-001 — XSS Prevention: unsafe HTML rendering without sanitization

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Перед рендерингом HTML применять `DOMPurify.sanitize(...)`, включить строгий CSP, избегать прямого HTML-injection в UI.

### FTS-002 — Sensitive data in client storage

- Source: `core/skills/domain-data-privacy/patterns.md`
- Safe-Pattern: Хранить чувствительные данные в httpOnly cookies/secure storage.

### FTS-003 — Sensitive console logging

- Source: `core/skills/domain-data-privacy/patterns.md`
- Safe-Pattern: Удалять/маскировать чувствительные поля в логах.

### FTS-004 — Insecure Communication: postMessage without origin validation

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Проверять `event.origin` через allowlist, использовать явный target origin вместо `"*"`, валидировать schema входящих сообщений.

### FTS-005 — Client-Side Logic Bypass: critical checks only in frontend

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Критичную бизнес-логику (цены, лимиты, ACL) дублировать и enforce на backend/API, фронтенд использовать только как UX слой.

### FTS-006 — Missing CSP Hardening for script execution

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Включить строгий CSP (`default-src 'self'`, nonce/hash для скриптов), запретить `unsafe-inline`/`unsafe-eval` в production.

### FTS-007 — Clickjacking Protection Missing

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Запретить embedding через `frame-ancestors 'none'` (или trusted list), добавить `X-Frame-Options: DENY/SAMEORIGIN`.

### FTS-008 — Source-map data exposure

- Source: `core/skills/domain-data-privacy/patterns.md`
- Safe-Pattern: Не публиковать source maps публично.

### FTS-009 — Dependency Integrity Missing for third-party scripts

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Использовать SRI (`integrity` + `crossorigin`) и pinning версий для внешних скриптов/виджетов.

### FTS-010 — Service Worker Cache Poisoning Risk

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Ограничить кэш только trusted-origin ресурсами, валидировать cache keys/versioning и отключать кэш для чувствительных ответов.

### FTS-011 — Unsafe Execution: dynamic code execution from strings

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Исключить string-based execution, использовать безопасные функции/колбэки и явные allowlist-парсеры вместо eval-подобных конструкций.

### FTS-012 — Prototype Pollution: unsafe deep merge without key guards

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Блокировать служебные ключи (`__proto__`, `constructor`, `prototype`), использовать безопасный merge и schema validation входа.

### FTS-013 — Global Namespace Pollution and native prototype extension

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Всегда использовать `const/let`, запретить расширение нативных прототипов и ограничить область видимости модулем/closure.

### FTS-014 — Insecure Pseudo-Random for security tokens

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Для токенов/идентификаторов использовать `window.crypto.getRandomValues()` и криптографически стойкие генераторы.

### FTS-015 — RegExp DoS / ReDoS with catastrophic backtracking

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Избегать уязвимых regex-конструкций, ограничивать длину входа и использовать безопасные/проверенные шаблоны.

### FTS-016 — Sequential Await DoS in loops for external calls

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Параллелизовать независимые запросы через `Promise.all()`/`Promise.allSettled()`, ограничивать concurrency и таймауты.

### FTS-017 — Unsafe Message Parsing in message handlers

- Source: `core/skills/domain-data-privacy/patterns.md`
- Safe-Pattern: Перед `JSON.parse` валидировать тип/размер `data`, origin/source, schema сообщения и обрабатывать parse errors безопасно.

### FTS-018 — Hidden UI Auth Bypass

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Enforce authorization на backend, не в UI.

### FTS-019 — Loose comparison in access checks

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Использовать `===`/strict types в auth ветках.

### FTS-020 — Unhandled Async Errors in Promise/async flows

- Source: `core/skills/domain-data-privacy/patterns.md`
- Safe-Pattern: Оборачивать async-цепочки в `try/catch`, добавлять `.catch(...)`, централизованный error boundary и rollback/compensation логику.

### GO-001 — Command Injection: `exec.Command("sh","-c", userInput)`

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `action := r.URL.Query().Get("action")`<br>`allowed := map[string][]string{"uptime": {"uptime"}}`<br>`...`<br>`exec.Command(allowed[action][0]).Run()`

### GO-002 — OS Exec Injection: `exec.Command("bash","-c",...)` с конкатенацией

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `host := r.URL.Query().Get("host")`<br>`if !hostRe.MatchString(host) { return }`<br>`...`<br>`exec.Command("ping", "-c", "1", host).Run()`

### GO-003 — Unsafe SQL Fragment Injection

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `order := r.URL.Query().Get("order")`<br>`if order != "name" && order != "created_at" { order = "name" }`<br>`...`<br>`q := "SELECT * FROM users ORDER BY " + order`

### GO-004 — Unsafe Reflection by Name

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `m := r.URL.Query().Get("method")`<br>`if m != "Health" && m != "Status" { return }`<br>`...`<br>`reflect.ValueOf(handler).MethodByName(m).Call(nil)`

### GO-005 — Plugin Loading from User Input

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `name := r.URL.Query().Get("plugin")`<br>`if _, ok := allowedPlugins[name]; !ok { return }`<br>`...`<br>`plugin.Open(allowedPlugins[name])`

### GO-006 — JavaScript Injection via goja/otto eval

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `cmd := r.FormValue("cmd")`<br>`if cmd != "normalize" { return }`<br>`...`<br>`vm.RunString("normalize(input)")`

### GO-007 — Template Expression Injection

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `name := r.FormValue("template")`<br>`if _, ok := safeTemplates[name]; !ok { return }`<br>`...`<br>`template.Must(template.ParseFiles(safeTemplates[name]))`

### GO-008 — Unsafe Command Router from User Field

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `tool := payload["tool"]`<br>`allowed := map[string][]string{"date": {"date"}}`<br>`if _, ok := allowed[tool.(string)]; !ok { return }`<br>`...`<br>`exec.Command(allowed[tool.(string)][0]).Run()`

### GO-009 — Goroutine Leak: бесконечная goroutine без `context`-остановки

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `go func(ctx context.Context) {`<br>`    for {`<br>`        select {`<br>`        case <-ctx.Done():`<br>`            return`<br>`        default:`<br>`            ...`<br>`        }`<br>`    }`<br>`}(ctx)`

### GO-010 — Path Traversal: небезопасный путь через `filepath.Join(root, userInput)`

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `name := r.URL.Query().Get("file")`<br>`clean := filepath.Clean("/" + name)`<br>`target := filepath.Join(root, clean)`<br>`if !strings.HasPrefix(target, root) {`<br>`    return`<br>`}`

### GO-011 — SSRF: прямой `http.Get(userInputURL)`

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `url := r.URL.Query().Get("url")`<br>`host := parseHost(url)`<br>`allowed := map[string]bool{"api.example.com": true}`<br>`if !allowed[host] {`<br>`    return`<br>`}`<br>`resp, _ := http.Get(url)`

### GO-012 — Unsafe Pointer Conversion: арифметика через `unsafe.Pointer`

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `buf := make([]byte, n)`<br>`...`<br>`_ = buf[offset:]`<br>`// avoid unsafe pointer arithmetic`

### GO-013 — Weak Crypto: использование MD5/SHA1

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `...`<br>`h := sha256.New()`

### GO-014 — Open Redirect: redirect на URL из query без проверки

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `next := r.URL.Query().Get("next")`<br>`if !isRelativeOrAllowed(next) {`<br>`    next = "/"`<br>`}`<br>`http.Redirect(w, r, next, http.StatusFound)`

### GO-015 — Log Injection: CR/LF в логах из пользовательского ввода

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `userInput := r.URL.Query().Get("user")`<br>`safe := strings.NewReplacer("\\n", "\\\\n", "\\r", "\\\\r").Replace(userInput)`<br>`...`<br>`log.Printf("User: %s", safe)`

### GO-016 — Hardcoded Credentials: секреты в константах/строках

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `apiKey := os.Getenv("API_KEY")`<br>`if apiKey == "" {`<br>`    panic("missing API_KEY")`<br>`}`

### GO-017 — Data Race: запись в общую переменную без `Mutex`

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `...`<br>`mu.Lock()`<br>`counter = counter + 1`<br>`mu.Unlock()`

### GO-018 — JWT Signature Validation Bypass: отсутствие проверки `alg` в `Keyfunc`

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {`<br>`    if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {`<br>`        return nil, fmt.Errorf("unexpected signing method")`<br>`    }`<br>`    return key, nil`<br>`})`

### GO-019 — DB Connection Leak: `db.Query` без `defer rows.Close()`

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `rows, err := db.Query(query)`<br>`if err != nil {`<br>`    return err`<br>`}`<br>`defer rows.Close()`<br>`...`

### GO-020 — Insecure TLS Config: `InsecureSkipVerify: true`

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `tr := &http.Transport{`<br>`    TLSClientConfig: &tls.Config{InsecureSkipVerify: false},`<br>`}`

### GO-021 — Unclosed File/Resource: `os.Open` без `defer Close()`

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `f, err := os.Open(path)`<br>`if err != nil {`<br>`    return err`<br>`}`<br>`defer f.Close()`<br>`...`

### GO-022 — Improper Output Encoding (XSS): небезопасный вывод пользовательского ввода

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `tmpl := template.Must(template.New("x").Parse("Hello {{.Name}}"))`<br>`...`<br>`tmpl.Execute(w, map[string]string{"Name": name})`

### GO-023 — Missing Request Body Limit: чтение тела без лимита

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `body, _ := io.ReadAll(io.LimitReader(r.Body, maxBytes))`<br>`...`<br>`_ = body`

### GO-024 — Debug Endpoint in Production: подключен `pprof` без feature flag

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `if debugEnabled {`<br>`    mux := http.NewServeMux()`<br>`    ...`<br>`    http.ListenAndServe("127.0.0.1:6060", mux)`<br>`}`

### GO-025 — gRPC Missing Auth: RPC метод без проверки metadata/auth

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `srv := grpc.NewServer(grpc.UnaryInterceptor(grpc_auth.UnaryServerInterceptor(authFunc)))`<br>`...`<br>`func authFunc(ctx context.Context) (context.Context, error) {`<br>`    md, _ := metadata.FromIncomingContext(ctx)`<br>`    ...`<br>`    return ctx, nil`<br>`}`

### GO-026 — Zip Slip: распаковка архива без проверки пути назначения

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `for _, f := range zipReader.File {`<br>`    targetPath := filepath.Join(dest, f.Name)`<br>`    clean := filepath.Clean(targetPath)`<br>`    if !strings.HasPrefix(clean, filepath.Clean(dest)+string(os.PathSeparator)) {`<br>`        return fmt.Errorf("zip slip detected")`<br>`    }`<br>`    writeFile(clean, f)`<br>`}`

### GO-027 — HTTP Proxy Header Injection: прямой прокси hop-by-hop заголовков

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `proxy := &httputil.ReverseProxy{`<br>`    Director: func(req *http.Request) {`<br>`        ...`<br>`        req.Header = cloneAllowedHeaders(r.Header)`<br>`        stripHopByHop(req.Header)`<br>`    },`<br>`}`

### GO-028 — Unsafe Reflect-based Deep Copy: рекурсивный `reflect` без type-guard

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `func CopyMessage(msg proto.Message) proto.Message {`<br>`    ...`<br>`    return proto.Clone(msg)`<br>`}`

### GO-029 — Hardcoded Root CAs: встроенные PEM в `tls.Config`

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `pem, err := os.ReadFile("/etc/ssl/certs/internal-ca.pem")`<br>`...`<br>`pool.AppendCertsFromPEM(pem)`

### GO-030 — gRPC Message Size Limit Missing: сервер без `MaxRecvMsgSize`

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `srv := grpc.NewServer(grpc.MaxRecvMsgSize(4*1024*1024))`<br>`...`<br>`pb.RegisterApiServer(srv, api)`

### GO-031 — Insecure Randomness: `math/rand` для токенов/секретов

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `b := make([]byte, 32)`<br>`...`<br>`if _, err := cryptorand.Read(b); err != nil {`<br>`    return err`<br>`}`

### GO-032 — Unbounded JSON Unmarshal: парсинг тела запроса без ограничения размера

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `raw, _ := io.ReadAll(io.LimitReader(r.Body, maxBytes))`<br>`...`<br>`json.Unmarshal(raw, &payload)`

### GO-033 — GORM Raw SQL Injection: конкатенация в `.Where()`/`.Raw()`

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `name := r.URL.Query().Get("name")`<br>`...`<br>`db.Where("name = ?", name).Find(&users)`<br>`...`<br>`db.Raw("SELECT * FROM users WHERE name = ?", name).Scan(&users)`

### GO-034 — Bypassing XSS protection via `template.HTML`

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `input := r.URL.Query().Get("html")`<br>`tmpl := template.Must(template.New("x").Parse("{{.Content}}"))`<br>`...`<br>`tmpl.Execute(w, map[string]string{"Content": input})`

### GO-035 — Sensitive Info Leak in Error Messages

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `err := someInternalError`<br>`...`<br>`log.Printf("internal error: %v", err)`<br>`return errors.New("internal server error")`

### GO-036 — Unsafe CGO Buffer: указатели в C без валидации буфера

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `buf := []byte(input)`<br>`cbuf := C.CBytes(buf)`<br>`defer C.free(cbuf)`<br>`...`<br>`C.process(cbuf)`

### GO-037 — Prototype Pollution / Map Assignment: копирование JSON-ключей без валидации

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `allowed := map[string]bool{"name": true, "email": true}`<br>`for k, v := range incomingMap {`<br>`    if allowed[k] {`<br>`        targetMap[k] = v`<br>`    }`<br>`}`

### GO-038 — Improper XML Entity Handling: парсер с дефолтными внешними сущностями

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `xmlParser := customxml.NewParser()`<br>`...`<br>`xmlParser.DisableExternalEntities(true)`<br>`xmlParser.Parse(rawXML)`

### GO-039 — Regex DoS (ReDoS): сложный regex на длинном пользовательском вводе

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `if len(longUserInput) > 2048 {`<br>`    return`<br>`}`<br>`re := regexp.MustCompile(userRegex)`<br>`...`<br>`re.MatchString(longUserInput)`

### GO-040 — Hardcoded JWT Secret: ключ подписи зашит в коде

- Source: `core/skills/go-core/patterns.md`
- Safe-Pattern: `jwtKey := []byte(os.Getenv("JWT_SECRET"))`<br>`if len(jwtKey) == 0 {`<br>`    panic("missing JWT_SECRET")`<br>`}`

### INF-010 — Hardcoded Credentials: захардкоженные пароли и токены в коде/манифестах

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `services:`<br>`  db:`<br>`    image: postgres:16`<br>`    environment:`<br>`      POSTGRES_PASSWORD_FILE: /run/secrets/postgres_password`<br>`      API_TOKEN_FILE: /run/secrets/api_token`<br>`secrets:`<br>`  postgres_password:`<br>`    file: ./secrets/postgres_password`<br>`  api_token:`<br>`    file: ./secrets/api_token`

### INF-011 — Committed Private Keys: приватные ключи в репозитории

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `tls.crt`<br>`tls.key`<br>`# secrets are provisioned at deploy time via external secret manager`<br>`apiVersion: external-secrets.io/v1beta1`<br>`kind: ExternalSecret`<br>`metadata:`<br>`  name: app-tls`<br>`spec:`<br>`  secretStoreRef:`<br>`    name: vault-store`<br>`    kind: ClusterSecretStore`<br>`  target:`<br>`    name: app-tls`<br>`  data:`<br>`  - secretKey: tls.key`<br>`    remoteRef:`<br>`      key: kv/prod/app/tls_key`

### INF-012 — Insecure .gitignore: секретные конфиги не исключены из Git

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `# .gitignore`<br>`.env`<br>`.env.*`<br>`secrets/`<br>`*.pem`<br>`*.key`<br>`*credentials*.json`<br>`!.env.example`

### INF-013 — Mutable Image Tags: использование `:latest` без digest pinning

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `apiVersion: apps/v1`<br>`kind: Deployment`<br>`spec:`<br>`  template:`<br>`    spec:`<br>`      containers:`<br>`      - name: api`<br>`        ...`<br>`        image: org/api@sha256:3b5f...`

### INF-014 — Auto-mounted ServiceAccount Token: токен пода доступен без необходимости

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `apiVersion: v1`<br>`kind: Pod`<br>`metadata:`<br>`  name: app-pod`<br>`spec:`<br>`  automountServiceAccountToken: false`<br>`  ...`<br>`  containers:`<br>`  - name: app`<br>`    image: org/app:1.0.0`

### INF-1.2.1 — API Server допускает anonymous auth

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `apiVersion: v1`<br>`kind: Pod`<br>`metadata:`<br>`  name: kube-apiserver`<br>`spec:`<br>`  containers:`<br>`  - name: kube-apiserver`<br>`    command:`<br>`    - kube-apiserver`<br>`    - --anonymous-auth=false # CIS: запрет неаутентифицированного доступа`

### INF-1.2.33 — Шифрование секретов в etcd не включено

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `apiVersion: v1`<br>`kind: Pod`<br>`metadata:`<br>`  name: kube-apiserver`<br>`spec:`<br>`  containers:`<br>`  - name: kube-apiserver`<br>`    command:`<br>`    - kube-apiserver`<br>`    - --encryption-provider-config=/etc/kubernetes/encryption-provider.yaml # CIS: encryption at rest for secrets`

### INF-1.2.6 — API Server без admission-control config файла

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `apiVersion: v1`<br>`kind: Pod`<br>`metadata:`<br>`  name: kube-apiserver`<br>`spec:`<br>`  containers:`<br>`  - name: kube-apiserver`<br>`    command:`<br>`    - kube-apiserver`<br>`    - --admission-control-config-file=/etc/kubernetes/admission-control.yaml # CIS: явно задать политику admission`

### INF-2.5.1 — NGINX раскрывает версию (`server_tokens on`)

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `server {`<br>`  listen 80;`<br>`  server_tokens off; # CIS: скрыть версию NGINX`<br>`}`

### INF-200 — Hardcoded employee identities in notification routes

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Вынести персоналии в защищенный справочник и role mapping.

### INF-201 — Missing CPU limits in workloads

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Обязательные CPU requests/limits по профилю сервиса.

### INF-202 — Missing memory limits in workloads

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Обязательные memory requests/limits и OOM policy.

### INF-203 — Unbounded worker autoscaling

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Вводить maxReplicas + circuit breaker на upstream.

### INF-204 — No pod disruption budget

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Добавить PDB для сохранения SLO при обновлениях/сбоях.

### INF-205 — Missing readiness probe

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Настроить readiness/liveness/startup probes.

### INF-206 — Missing startup probe for heavy services

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Добавить startup probe с корректным timeout window.

### INF-207 — No network egress policy

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Egress allowlist через NetworkPolicy/egress proxy.

### INF-208 — Unpinned base image digest

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Использовать digest pinning + controlled updates.

### INF-209 — Missing SBOM attestation in release flow

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Генерировать и хранить SBOM + provenance attestation.

### INF-210 — Unencrypted internal traffic

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Включить service mesh mTLS/PKI policy.

### INF-211 — No centralized secret rotation

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Политика ротации и автоматический rollover.

### INF-212 — Privileged debug containers in production

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Запрет privileged debug в prod namespace.

### INF-213 — Missing immutable config boundary

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Immutable config + signed deployment pipeline.

### INF-214 — No resource quota per namespace

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Ввести ResourceQuota и LimitRange.

### INF-215 — Missing audit retention policy

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Политика хранения/архивации security logs.

### INF-216 — No rollback safety gate

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Canary + auto rollback on SLO breach.

### INF-217 — Exposed admin endpoints internally without auth

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: mTLS + authn/authz даже во внутреннем контуре.

### INF-218 — Missing runtime seccomp/apparmor baseline

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Применить baseline профили на namespace/service.

### INF-219 — No node taint/toleration isolation

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Изоляция узлов через taints/tolerations/nodeSelector.

### INF-220 — Incident notification without rate control

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Ввести dedup/throttle и escalation policy.

### INF-4.1 — Dockerfile без выделенного непривилегированного пользователя

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `FROM python:3.11`<br>`WORKDIR /app`<br>`RUN groupadd -r app && useradd -r -g app app`<br>`COPY . /app`<br>`RUN chown -R app:app /app`<br>`USER app`<br>`CMD ["python","main.py"]`

### INF-4.4 — Dockerfile содержит секреты в `ENV`/`LABEL`

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `FROM python:3.11`<br>`ENV DB_PASSWORD_FILE=/run/secrets/db_password`<br>`LABEL security.secrets=\"external-secret-store\" # no plaintext secrets`

### INF-5.1.1 — Избыточное использование `cluster-admin`

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `apiVersion: rbac.authorization.k8s.io/v1`<br>`kind: Role`<br>`metadata:`<br>`  name: app-read-only`<br>`  namespace: app`<br>`rules:`<br>`- apiGroups: [""]`<br>`  resources: ["pods","services"]`<br>`  verbs: ["get","list","watch"] # CIS: минимум привилегий`<br>`---`<br>`apiVersion: rbac.authorization.k8s.io/v1`<br>`kind: RoleBinding`<br>`metadata:`<br>`  name: app-read-only-binding`<br>`  namespace: app`<br>`subjects:`<br>`- kind: ServiceAccount`<br>`  name: app-sa`<br>`  namespace: app`<br>`roleRef:`<br>`  kind: Role`<br>`  name: app-read-only`<br>`  apiGroup: rbac.authorization.k8s.io`

### INF-5.1.2-TLS — Разрешены TLS 1.0/1.1 в NGINX

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `server {`<br>`  listen 443 ssl;`<br>`  ssl_protocols TLSv1.2 TLSv1.3; # CIS: disable legacy TLS`<br>`}`

### INF-5.10 — Нет ограничений памяти и CPU для контейнера

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `services:`<br>`  api:`<br>`    image: example/api:1.0.0`<br>`    mem_limit: "512m"`<br>`    cpu_shares: 512`

### INF-5.2.1 — Привилегированный контейнер используется

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `apiVersion: v1`<br>`kind: Pod`<br>`metadata:`<br>`  name: restricted-pod`<br>`spec:`<br>`  containers:`<br>`  - name: app`<br>`    image: nginx:1.27`<br>`    securityContext:`<br>`      privileged: false`

### INF-5.2.4 — `allowPrivilegeEscalation` не запрещен

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `apiVersion: apps/v1`<br>`kind: Deployment`<br>`metadata:`<br>`  name: ape-off`<br>`spec:`<br>`  template:`<br>`    spec:`<br>`      containers:`<br>`      - name: app`<br>`        image: example/app:1.0.0`<br>`        securityContext:`<br>`          allowPrivilegeEscalation: false`

### INF-5.2.5 — Контейнер запускается с root GID

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `apiVersion: v1`<br>`kind: Pod`<br>`metadata:`<br>`  name: non-root-gid`<br>`spec:`<br>`  containers:`<br>`  - name: app`<br>`    image: example/app:1.0.0`<br>`    securityContext:`<br>`      runAsNonRoot: true`<br>`      runAsGroup: 10001`

### INF-5.25 — Монтирование `/var/run/docker.sock` в контейнер

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `apiVersion: v1`<br>`kind: Pod`<br>`metadata:`<br>`  name: no-docker-sock`<br>`spec:`<br>`  containers:`<br>`  - name: app`<br>`    image: alpine:3.20`<br>`    volumeMounts:`<br>`    - name: app-tmp`<br>`      mountPath: /tmp`<br>`  volumes:`<br>`  - name: app-tmp`<br>`    emptyDir: {}`

### INF-5.3.1 — NetworkPolicies не определены

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `apiVersion: networking.k8s.io/v1`<br>`kind: NetworkPolicy`<br>`metadata:`<br>`  name: app-default-deny`<br>`  namespace: default`<br>`spec:`<br>`  podSelector:`<br>`    matchLabels:`<br>`      app: app`<br>`  policyTypes:`<br>`  - Ingress`<br>`  - Egress`<br>`  ingress: []`<br>`  egress: []`

### INF-5.3.1-NGX — NGINX без X-Frame-Options

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `server {`<br>`  listen 443 ssl;`<br>`  add_header X-Frame-Options "DENY" always; # CIS: разрешено DENY или SAMEORIGIN`<br>`  location / { proxy_pass http://app; }`<br>`}`

### INF-5.3.2 — NGINX без Content-Security-Policy

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `server {`<br>`  listen 443 ssl;`<br>`  add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'self'; object-src 'none'" always; # CIS: CSP обязателен`<br>`  location / { proxy_pass http://app; }`<br>`}`

### INF-5.5.1 — Не ограничены HTTP-методы

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `location /api/ {`<br>`  limit_except GET POST HEAD {`<br>`    deny all; # CIS: allow only approved methods`<br>`  }`<br>`  proxy_pass http://backend;`<br>`}`

### INF-5.6.2 — Pod без seccomp профиля

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `apiVersion: v1`<br>`kind: Pod`<br>`metadata:`<br>`  name: with-seccomp`<br>`spec:`<br>`  containers:`<br>`  - name: app`<br>`    image: nginx:1.27`<br>`    securityContext:`<br>`      seccompProfile:`<br>`        type: RuntimeDefault # CIS: docker/default или runtime/default`

### INS-001 — Electron Insecure Content Isolation

- Source: `core/skills/desktop-vsto-suite/patterns.md`
- Safe-Pattern: `contextIsolation: true` + `preload` скрипт без прямого `nodeIntegration` в рендере

### INS-002 — Electron Node Integration Leak

- Source: `core/skills/desktop-vsto-suite/patterns.md`
- Safe-Pattern: `nodeIntegration: false` для окон с внешним/непроверенным контентом

### INS-003 — Electron Insecure IPC

- Source: `core/skills/desktop-vsto-suite/patterns.md`
- Safe-Pattern: `ipcMain.handle` + схема валидации (zod/io-ts) + запрет `eval`/`new Function`

### INS-004 — .NET 4.8 / VSTO Legacy Deserialization

- Source: `core/skills/desktop-vsto-suite/patterns.md`
- Safe-Pattern: `JsonConvert.DeserializeObject<T>(...)` с известными типами или `DataContractSerializer` с allowlist

### INS-005 — VSTO Insecure XML

- Source: `core/skills/desktop-vsto-suite/patterns.md`
- Safe-Pattern: `settings.DtdProcessing = DtdProcessing.Prohibit;` + `XmlReader.Create` с `XmlReaderSettings`

### INS-006 — NSIS DLL Hijacking

- Source: `core/skills/desktop-vsto-suite/patterns.md`
- Safe-Pattern: `!insertmacro SetDefaultDllDirectories` в начале скрипта (до секций с `File`)

### INS-007 — VSTO Cleartext Password in Config

- Source: `core/skills/desktop-vsto-suite/patterns.md`
- Safe-Pattern: `ProtectedData.Protect` / DPAPI / Azure Key Vault / секреты вне `app.config`

### INS-008 — Electron Production Debugging

- Source: `core/skills/desktop-vsto-suite/patterns.md`
- Safe-Pattern: `if (isDev) { mainWindow.webContents.openDevTools(); }`

### ITS-001 — Keycloak JWT: отключена проверка подписи/issuer/audience

- Source: `core/skills/integration-security/patterns.md`
- Safe-Pattern: Валидация подписи (`JWKS`), `iss`, `aud`, `exp`, `nbf`, deny unknown alg.

### ITS-002 — Vault: хардкод секретов/токенов в коде и конфиге

- Source: `core/skills/integration-security/patterns.md`
- Safe-Pattern: Аутентификация в Vault через AppRole/Kubernetes auth, short-lived tokens, secret retrieval только во время runtime.

### ITS-003 — K8s интеграции без External Secrets Operator

- Source: `core/skills/integration-security/patterns.md`
- Safe-Pattern: Использовать External Secrets Operator + Vault/SM backend, исключить прямой plaintext секрет в манифестах.

### ITS-004 — Circuit Breaker: голые вызовы Клинкера/API без предохранителей

- Source: `core/skills/integration-security/patterns.md`
- Safe-Pattern: Использовать circuit breaker (`pybreaker`, `resilience4j`, аналоги), fallback и метрики отказов по внешним интеграциям.

### ITS-005 — Bulkhead & Timeouts: HTTP-вызовы без timeout и без лимитов пула

- Source: `core/skills/integration-security/patterns.md`
- Safe-Pattern: Всегда задавать timeout и ограничивать connection pool (bulkhead), чтобы избежать каскадных сбоев при деградации внешних API.

### ITS-006 — Retry Storm: без retry budget и jitter

- Source: `core/skills/integration-security/patterns.md`
- Safe-Pattern: Ограничивать retries через retry budget, exponential backoff и jitter; прерывать цикл при circuit-open состоянии.

### ITS-007 — Idempotency Gap: платежные API без idempotency ключей

- Source: `core/skills/integration-security/patterns.md`
- Safe-Pattern: Для критичных операций использовать `Idempotency-Key`, deduplication window и журнал повторных запросов.

### JAVA-001 — Java Eval Injection: выполнение выражения из пользовательского ввода

- Source: `core/skills/java-spring/patterns.md`
- Safe-Pattern: `String expr = request.getParameter("expr");`<br>`if (!expr.matches("^[0-9+\\-*/(). ]{1,64}$")) throw new IllegalArgumentException();`<br>`...`<br>`Object result = safeMathEval(expr);`

### JAVA-002 — Runtime Exec Injection: `Runtime.getRuntime().exec` со строкой команды

- Source: `core/skills/java-spring/patterns.md`
- Safe-Pattern: `String host = req.getParameter("host");`<br>`if (!host.matches("^[a-zA-Z0-9.-]{1,255}$")) throw new IllegalArgumentException();`<br>`...`<br>`new ProcessBuilder("ping","-c","1",host).start();`

### JAVA-003 — ProcessBuilder Command Injection: shell-строка через `/bin/sh -c`

- Source: `core/skills/java-spring/patterns.md`
- Safe-Pattern: `String action = req.getParameter("action");`<br>`Map<String,List<String>> allowed = Map.of("uptime", List.of("uptime"));`<br>`...`<br>`new ProcessBuilder(allowed.get(action)).start();`

### JAVA-004 — Unsafe Reflection: загрузка класса из пользовательского ввода

- Source: `core/skills/java-spring/patterns.md`
- Safe-Pattern: `String key = req.getParameter("handler");`<br>`Map<String,Class<?>> allow = Map.of("health", HealthHandler.class);`<br>`...`<br>`Class<?> c = allow.get(key);`

### JAVA-005 — Method Invocation Injection: вызов произвольного метода через reflection

- Source: `core/skills/java-spring/patterns.md`
- Safe-Pattern: `String method = req.getParameter("method");`<br>`Set<String> allow = Set.of("health","status");`<br>`if (!allow.contains(method)) throw new SecurityException();`<br>`...`<br>`target.getClass().getMethod(method).invoke(target);`

### JAVA-006 — JDBC Command Composition: SQL/command фрагмент из input без allowlist

- Source: `core/skills/java-spring/patterns.md`
- Safe-Pattern: `String order = req.getParameter("order");`<br>`if (!Set.of("name","created_at").contains(order)) order = "name";`<br>`...`<br>`String q = "SELECT * FROM users ORDER BY " + order;`

### JAVA-007 — SpEL Injection: expression parser на пользовательских данных

- Source: `core/skills/java-spring/patterns.md`
- Safe-Pattern: `String key = req.getParameter("key");`<br>`Map<String,String> allow = Map.of("env","prod");`<br>`...`<br>`return allow.getOrDefault(key, "n/a");`

### JAVA-008 — Nashorn/Graal JS Injection: выполнение произвольного JS кода

- Source: `core/skills/java-spring/patterns.md`
- Safe-Pattern: `String cmd = req.getParameter("cmd");`<br>`if (!Set.of("normalize").contains(cmd)) throw new SecurityException();`<br>`...`<br>`runFixedJsFunction(cmd);`

### JAVA-009 — SpEL Injection (Spring): expression из запроса исполняется в контексте

- Source: `core/skills/java-spring/patterns.md`
- Safe-Pattern: `String key = request.getParameter("key");`<br>`Map<String,Object> allowed = Map.of("health", true);`<br>`...`<br>`return allowed.getOrDefault(key, false);`

### JAVA-010 — Jackson Unsafe Deserialization: default typing на недоверенных данных

- Source: `core/skills/java-spring/patterns.md`
- Safe-Pattern: `ObjectMapper mapper = new ObjectMapper();`<br>`...`<br>`mapper.disableDefaultTyping();`<br>`UserDTO obj = mapper.readValue(body, UserDTO.class);`

### JAVA-011 — Log4j/JNDI Deserialization Risk: логирование сырых user-строк

- Source: `core/skills/java-spring/patterns.md`
- Safe-Pattern: `String msg = request.getParameter("msg");`<br>`String safe = msg.replace("${", "\\${");`<br>`...`<br>`logger.error("msg={}", safe);`

### JAVA-012 — XXE in XML Parsers: внешние сущности не запрещены

- Source: `core/skills/java-spring/patterns.md`
- Safe-Pattern: `DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();`<br>`f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);`<br>`f.setFeature("http://xml.org/sax/features/external-general-entities", false);`<br>`f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);`

### JAVA-013 — Insecure Spring Security: `permitAll()` на критичных эндпоинтах

- Source: `core/skills/java-spring/patterns.md`
- Safe-Pattern: `http.authorizeHttpRequests(auth -> auth`<br>`    .requestMatchers("/admin/**").hasRole("ADMIN")`<br>`);`

### JAVA-014 — CSRF Disabled Globally в stateful приложении

- Source: `core/skills/java-spring/patterns.md`
- Safe-Pattern: `http.csrf(csrf -> csrf`<br>`    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())`<br>`);`

### JAVA-015 — Open Redirect in Spring MVC

- Source: `core/skills/java-spring/patterns.md`
- Safe-Pattern: `String next = request.getParameter("next");`<br>`if (!next.startsWith("/")) next = "/";`<br>`...`<br>`return "redirect:" + next;`

### JAVA-016 — JWT Signature Bypass: no alg check in parser

- Source: `core/skills/java-spring/patterns.md`
- Safe-Pattern: `JwsHeader<?> h = Jwts.parserBuilder().build().parseClaimsJws(token).getHeader();`<br>`if (!"HS256".equals(h.getAlgorithm())) throw new SecurityException();`<br>`Claims c = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();`

### JAVA-017 — Insecure Random for tokens (`java.util.Random`)

- Source: `core/skills/java-spring/patterns.md`
- Safe-Pattern: `SecureRandom r = new SecureRandom();`<br>`...`<br>`byte[] token = new byte[32];`<br>`r.nextBytes(token);`

### JAVA-018 — Hardcoded Secrets in config/code

- Source: `core/skills/java-spring/patterns.md`
- Safe-Pattern: `String jwtSecret = System.getenv("JWT_SECRET");`<br>`if (jwtSecret == null) throw new IllegalStateException();`

### JAVA-019 — Unbounded Multipart Upload (DoS risk)

- Source: `core/skills/java-spring/patterns.md`
- Safe-Pattern: `if (file.getSize() > 5 * 1024 * 1024) throw new IllegalArgumentException();`<br>`...`<br>`byte[] data = file.getBytes();`

### JAVA-020 — Path Traversal in file download

- Source: `core/skills/java-spring/patterns.md`
- Safe-Pattern: `String p = request.getParameter("path");`<br>`Path target = Paths.get(root, p).normalize();`<br>`if (!target.startsWith(Paths.get(root))) throw new SecurityException();`

### K8S-010 — Missing capabilities drop (`ALL`)

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `securityContext:`<br>`  allowPrivilegeEscalation: false`<br>`  capabilities:`<br>`    drop: ["ALL"]`

### K8S-011 — Host networking enabled

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `spec:`<br>`  hostNetwork: false`

### K8S-012 — Host PID namespace enabled

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `spec:`<br>`  hostPID: false`

### K8S-013 — Host IPC namespace enabled

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `spec:`<br>`  hostIPC: false`

### K8S-014 — Missing readOnlyRootFilesystem

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `securityContext:`<br>`  readOnlyRootFilesystem: true`

### K8S-015 — runAsNonRoot not enforced

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `securityContext:`<br>`  runAsNonRoot: true`

### K8S-016 — AppArmor profile not set

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `metadata:`<br>`  annotations:`<br>`    container.apparmor.security.beta.kubernetes.io/app: runtime/default`

### K8S-017 — Seccomp profile Unconfined

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `seccompProfile:`<br>`  type: RuntimeDefault`

### K8S-018 — No liveness probe

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `containers:`<br>`- name: api`<br>`  livenessProbe:`<br>`    httpGet:`<br>`      path: /healthz`

### K8S-019 — No readiness probe

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `containers:`<br>`- name: api`<br>`  readinessProbe:`<br>`    httpGet:`<br>`      path: /ready`

### K8S-020 — No resource limits

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `resources:`<br>`  limits:`<br>`    cpu: "500m"`<br>`    memory: "512Mi"`

### K8S-021 — NetworkPolicy absent for namespace

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `kind: NetworkPolicy`<br>`metadata:`<br>`  namespace: prod`<br>`spec:`<br>`  policyTypes: ["Ingress","Egress"]`

### K8S-022 — Service of type NodePort exposed by default

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `kind: Service`<br>`spec:`<br>`  type: ClusterIP`

### K8S-023 — Wildcard RBAC verbs/resources

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `verbs: ["get","list"]`<br>`resources: ["pods"]`

### K8S-024 — automountServiceAccountToken enabled

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `automountServiceAccountToken: false`

### K8S-025 — Latest image tag in workload

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `image: org/api@sha256:abcd...`

### LIC-001 — AGPL-3.0 in `package.json` / `requirements.txt`

- Source: `core/skills/license-compliance/patterns.md`
- Safe-Pattern: Заменить AGPL зависимость на совместимую по лицензии (MIT/BSD/Apache-2.0) и проверить транзитивные зависимости (lockfile/SBOM).

### LIC-002 — SSPL for hosted/cloud services

- Source: `core/skills/license-compliance/patterns.md`
- Safe-Pattern: Исключить SSPL зависимости в облачном контуре, заменить на permissive варианты и подтвердить лицензионную совместимость (SBOM/scan).

### LIC-003 — Unmaintained / deprecated library (> 2 years)

- Source: `core/skills/license-compliance/patterns.md`
- Safe-Pattern: Обновить библиотеку до поддерживаемой версии, либо заменить на альтернативу с активным мейнтейном; фиксировать версии в lockfile.

### LIC-004 — Unknown License Metadata

- Source: `core/skills/license-compliance/patterns.md`
- Safe-Pattern: Разрешать только явно идентифицированные SPDX-лицензии; блокировать сборку при `UNKNOWN`/`NOASSERTION`.

### LIC-005 — Untrusted Package Source

- Source: `core/skills/license-compliance/patterns.md`
- Safe-Pattern: Использовать только доверенные внутренние registry/mirror и фиксировать источник в CI policy.

### LIC-006 — Missing License Gate in CI

- Source: `core/skills/license-compliance/patterns.md`
- Safe-Pattern: Добавить CI gate: `syft` + policy check (block on AGPL/GPL/SSPL according to org policy).

### LIC-008 — Missing SBOM Evidence

- Source: `core/skills/license-compliance/patterns.md`
- Safe-Pattern: Генерировать SBOM через `syft` в формате CycloneDX/SPDX и сохранять как артефакт релиза.

### LIC-009 — Transitive Copyleft via Syft

- Source: `core/skills/license-compliance/patterns.md`
- Safe-Pattern: Анализировать `syft`-отчет на транзитивные copyleft-лицензии и блокировать релиз до remediation/exception approval.

### LIC-010 — Binary-embedded License Risk

- Source: `core/skills/license-compliance/patterns.md`
- Safe-Pattern: Для бинарных зависимостей проверять наличие license metadata/attestation и подтверждать источник/право использования.

### LOG-001 — Silent Exception: `except Exception: pass`

- Source: `core/skills/observability/patterns.md`
- Safe-Pattern: `try:`<br>`    await repo.save(event)`<br>`except Exception:`<br>`    logger.exception("audit-save-failed", extra={"event_type": event.type})`<br>`    raise`

### LOG-002 — Missing Trace-ID в логах запроса

- Source: `core/skills/observability/patterns.md`
- Safe-Pattern: `trace_id = request.headers.get("x-trace-id") or str(uuid4())`<br>`logger.info("request accepted", extra={"trace_id": trace_id, "path": request.url.path})`<br>`response.headers["X-Trace-ID"] = trace_id`

### LOG-003 — Unstructured logs: текст без контекста безопасности

- Source: `core/skills/observability/patterns.md`
- Safe-Pattern: `logger.warning("auth_failed", extra={"trace_id": trace_id, "user": username, "ip": client_ip, "reason": "bad_credentials"})`

### LOG-004 — PII/secret leakage in logs

- Source: `core/skills/observability/patterns.md`
- Safe-Pattern: `safe = {"username": payload.get("username"), "mfa": payload.get("mfa")}`<br>`logger.info("auth payload sanitized", extra={"trace_id": trace_id, "payload": safe})`

### LOG-005 — Verbose stack traces returned to API client

- Source: `core/skills/observability/patterns.md`
- Safe-Pattern: `except Exception:`<br>`    logger.exception("unhandled error", extra={"trace_id": trace_id})`<br>`    raise HTTPException(status_code=500, detail="internal server error")`

### LOG-006 — Missing audit events for role/permission changes

- Source: `core/skills/observability/patterns.md`
- Safe-Pattern: `@app.post("/admin/users/{uid}/role")`<br>`async def set_role(uid: int, role: str, actor=Depends(current_user)):`<br>`    await repo.set_role(uid, role)`<br>`    await audit_log.write({"event": "role_change", "actor_id": actor.id, "target_user_id": uid, "new_role": role, "trace_id": trace_id})`

### LOG-007 — Missing failed-auth telemetry and lockout signals

- Source: `core/skills/observability/patterns.md`
- Safe-Pattern: `if not auth_ok:`<br>`    await audit_log.write({"event": "auth_failed", "username": username, "ip": client_ip, "trace_id": trace_id})`<br>`    await risk_counter.bump(f"auth:{username}:{client_ip}")`<br>`    raise HTTPException(status_code=401, detail="invalid credentials")`

### LOG-008 — No request/response latency telemetry

- Source: `core/skills/observability/patterns.md`
- Safe-Pattern: `@app.middleware("http")`<br>`async def m(request: Request, call_next):`<br>`    started = time.perf_counter()`<br>`    response = await call_next(request)`<br>`    elapsed_ms = (time.perf_counter() - started) * 1000`<br>`    logger.info("http_access", extra={"trace_id": request.state.trace_id, "path": request.url.path, "status": response.status_code, "latency_ms": round(elapsed_ms, 2)})`<br>`    return response`

### LOG-009 — Logs without integrity controls/immutability for security events

- Source: `core/skills/observability/patterns.md`
- Safe-Pattern: `record = {"event": "payment_approved", "id": pid, "trace_id": trace_id, "ts": datetime.now(timezone.utc).isoformat()}`<br>`record["sig"] = hmac_sha256(audit_signing_key, json.dumps(record, sort_keys=True))`<br>`await append_only_audit_store.write(record)`

### LOG-010 — No centralized exception handler for sanitization and correlation

- Source: `core/skills/observability/patterns.md`
- Safe-Pattern: `@app.exception_handler(Exception)`<br>`async def handle_exc(request: Request, exc: Exception):`<br>`    trace_id = getattr(request.state, "trace_id", "n/a")`<br>`    logger.exception("unhandled", extra={"trace_id": trace_id, "path": request.url.path})`<br>`    return JSONResponse(status_code=500, content={"detail": "internal server error", "trace_id": trace_id})`

### LOG-011 — Log Injection Protection: CR/LF из пользовательских данных попадают в лог

- Source: `core/skills/observability/patterns.md`
- Safe-Pattern: `def sanitize_for_log(value: str) -> str:`<br>`    return value.replace("\\r", "\\\\r").replace("\\n", "\\\\n")`<br>`@app.get("/search")`<br>`async def search(q: str):`<br>`    safe_q = sanitize_for_log(q)`<br>`    logger.info("search query=%s", safe_q)`<br>`    return {"ok": True}`

### LOG-012 — Sensitive Data in Exception Context: логирование `locals()` в prod

- Source: `core/skills/observability/patterns.md`
- Safe-Pattern: `except Exception:`<br>`    logger.exception("failed", extra={"trace_id": trace_id, "context": {"operation": "payment_create"}})`<br>`    raise`<br>`# production logger must not capture locals or full frame dumps`

### LOG-013 — Missing Security Heartbeat: нет периодических контрольных событий мониторинга

- Source: `core/skills/observability/patterns.md`
- Safe-Pattern: `async def security_heartbeat_task() -> None:`<br>`    while True:`<br>`        await audit_log.write({"event": "security_heartbeat", "service": "api", "status": "ok", "ts": datetime.now(timezone.utc).isoformat()})`<br>`        await asyncio.sleep(60)`<br>`@app.on_event("startup")`<br>`async def start_heartbeat() -> None:`<br>`    asyncio.create_task(security_heartbeat_task())`

### LOG-014 — High-Privilege Action Audit: админ-действия пишутся в обычный app log

- Source: `core/skills/observability/patterns.md`
- Safe-Pattern: `@app.post("/admin/users/{uid}/disable")`<br>`async def disable_user(uid: int, actor=Depends(current_user)):`<br>`    logger.info("admin action requested", extra={"trace_id": trace_id, "actor_id": actor.id})`<br>`    await security_audit_log.write({"event": "admin_user_disable", "actor_id": actor.id, "target_user_id": uid, "trace_id": trace_id, "ts": datetime.now(timezone.utc).isoformat()})`

### MOB-001 — Flutter TLS bypass

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Удалить bypass, включить pinning/strict TLS validation.

### MOB-010 — Token leakage in debug mode

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Никогда не печатать токены, даже в debug.

### MOB-021 — Missing UI privacy protection

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Включить `FLAG_SECURE` на чувствительных экранах.

### NGX-001 — HSTS header missing

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;`

### NGX-002 — Content-Security-Policy missing

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `add_header Content-Security-Policy "default-src 'self'" always;`

### NGX-003 — X-Content-Type-Options missing

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `add_header X-Content-Type-Options "nosniff" always;`

### NGX-004 — X-Frame-Options missing

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `add_header X-Frame-Options "DENY" always;`

### NGX-005 — Weak TLS protocols enabled

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `ssl_protocols TLSv1.2 TLSv1.3;`

### NGX-006 — TLS 1.3 not enforced for strict profile

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `ssl_protocols TLSv1.3;`

### NGX-007 — No request rate limiting

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;`

### NGX-008 — Client body size unlimited

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `client_max_body_size 10m;`

### NGX-009 — Proxy timeouts missing

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `proxy_connect_timeout 5s; proxy_read_timeout 30s;`

### NGX-010 — server_tokens enabled

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `server_tokens off;`

### NJS-001 — Command injection in exec

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: `execFile/spawn` + allowlist args.

### NJS-002 — Path traversal in fs access

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: `path.resolve` + strict base boundary checks.

### NJS-003 — Event Loop Blocking через `*Sync` API в request handlers

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: В обработчиках запросов использовать async API (`fs.promises`, async zlib/crypto), выносить CPU-heavy задачи в worker queue/thread.

### NJS-004 — Insecure Serialization / unsafe eval processing

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Запретить `node-serialize` и eval-подобный парсинг; использовать `JSON.parse` + schema validation.

### NJS-005 — Missing process crash guards for async/runtime failures

- Source: `core/skills/domain-data-privacy/patterns.md`
- Safe-Pattern: Добавить обработчики `uncaughtException`/`unhandledRejection` с audit logging, graceful shutdown и restart strategy.

### NJS-006 — Open Redirect via untrusted URL forwarding

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Валидировать redirect targets по allowlist доменов/путей, запрещать внешние схемы и абсолютные URL без проверки.

### NJS-007 — SSRF in fetch

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: URL allowlist + deny private/link-local.

### NJS-008 — Broken CORS policy with wildcard + credentials

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Использовать строгий allowlist origin и отключать credentials для wildcard.

### NJS-009 — JWT verify without strict policy

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Явный `algorithms` allowlist + проверки `iss/aud/exp/nbf`.

### NJS-010 — Stacktrace leakage in API

- Source: `core/skills/domain-data-privacy/patterns.md`
- Safe-Pattern: Клиенту только generic message, детали в secure logs.

### NJS-011 — Server-Side Prototype Pollution in merge/parsing flows

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Блокировать `__proto__`/`constructor`/`prototype`, использовать safe-merge и schema validation для входных структур.

### NJS-012 — Unsafe Buffer allocation

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Использовать `Buffer.alloc()` или контролируемое заполнение буфера перед чтением, чтобы исключить утечку памяти.

### NJS-013 — HTTP Parameter Pollution without type guards

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Явно валидировать типы `req.query/req.body` (string/array/object) и нормализовать параметры до бизнес-логики.

### NJS-014 — Insecure Sandbox with `vm` module execution

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Не исполнять недоверенный код через `vm`; использовать изолированные микросервисы/контейнеры или специализированные sandbox-подходы с жесткими ограничениями.

### NJS-015 — Event Loop ReDoS in server validators/routes

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Исключать regex с catastrophic backtracking, ограничивать input length и использовать безопасные/предкомпилированные паттерны.

### NJS-016 — Missing ownership check (IDOR/BOLA)

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Проверять `resource.ownerId == req.user.id` до выдачи объекта.

### NJS-017 — Dependency integrity gaps

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Lockfile + pinned versions + private registry policy.

### NJS-018 — Header fingerprint leakage

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: `helmet()` + disable x-powered-by.

### NJS-019 — Abuse of process.env directly in business logic

- Source: `core/skills/domain-data-privacy/patterns.md`
- Safe-Pattern: Читать env только через централизованный config service с type validation (convict/ConfigService) и неизменяемым контрактом настроек.

### NJS-020 — Unsafe File Deletion/Cleanup with user-controlled paths

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Перед удалением нормализовать/resolve путь и проверять, что он находится в разрешенной temp/work директории.

### NJS-021 — Missing request payload size limits (DoS risk)

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Ограничить размер body (`express.json({ limit: "1mb" })`), задавать per-route лимиты для upload endpoints.

### NJS-022 — Weak password hashing parameters

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Использовать достаточный work factor (например, 12+), периодически пересматривать параметры согласно hardware baseline.

### NJS-023 — NoSQL Injection in Mongo-style filters

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Валидировать и нормализовать input, запрещать операторы `$ne/$gt/$where` из пользовательских payload-ов.

### NJS-024 — Weak session cookie policy

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: `httpOnly`, `secure`, `sameSite`, rotation, revoke on logout.

### NJS-025 — Open CORS preflight methods/headers overexposure

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Ограничивать `methods/allowedHeaders` минимумом необходимого, синхронизировать с API contract/allowlist.

### NJS-026 — Mass Assignment через прямую передачу `req.body` в ORM

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Использовать allowlist полей (DTO/pick), игнорировать системные атрибуты и критичные security-флаги при mass update.

### NJS-027 — Safe Buffer Creation: `Buffer.from(variable)` без type guard

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Перед созданием буфера валидировать тип входа (`string`/`Uint8Array`) и исключить невалидные/числовые источники данных.

### NJS-028 — SCA / Audit Gate отсутствует в npm scripts

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Добавить обязательный SCA gate в CI (`npm audit --audit-level=high`/`snyk test`/`socket protect`) и fail build на критичных уязвимостях.

### NJS-029 — SSTI / Unsafe template raw output tags

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Использовать экранированный вывод (`<%= ... %>`) и санитизацию HTML перед рендерингом динамического контента.

### NJS-030 — JSON Depth/Size Limits missing in body parsing

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Ограничить размер payload (`limit`) и глубину вложенности через schema validator/middleware, отклонять аномально глубокие JSON.

### NJS-031 — Prototype Pollution через spread operator из user input

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Перед spread очищать опасные ключи (`__proto__`, `constructor`, `prototype`) и валидировать объект schema-based guard-ом.

### NJS-032 — Insecure JWT Secret Storage via direct env read

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Получать JWT secrets через Secret Manager/Vault/KMS abstraction с ротацией и аудитом доступа, не читать напрямую в runtime logic.

### NJS-033 — Weak TLS config

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Строгая проверка сертификатов и trust policy.

### NJS-034 — Unsafe stream piping without error handlers

- Source: `core/skills/domain-data-privacy/patterns.md`
- Safe-Pattern: Обрабатывать ошибки обоих stream endpoints, использовать `pipeline(...)`/`finished(...)` для корректного cleanup ресурсов.

### NJS-035 — Sensitive data retained in long-lived heap strings

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Минимизировать lifetime чувствительных данных, избегать хранения plaintext в памяти и очищать буферы после использования.

### NST-001 — Prototype Pollution в DTO merge

- Source: `core/skills/nodejs-nestjs/patterns.md`
- Safe-Pattern: `const dto = req.body`<br>`...`<br>`for (const k of Object.keys(dto)) {`<br>`  if (["__proto__", "constructor", "prototype"].includes(k)) throw new Error("blocked")`<br>`}`

### NST-002 — Insecure CORS (`origin: *`)

- Source: `core/skills/nodejs-nestjs/patterns.md`
- Safe-Pattern: `app.enableCors({ origin: ["https://app.example.com"], credentials: true })`

### NST-003 — Missing global ValidationPipe

- Source: `core/skills/nodejs-nestjs/patterns.md`
- Safe-Pattern: `const app = await NestFactory.create(AppModule)`<br>`app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))`

### NST-004 — TypeORM SQL Injection (query string concat)

- Source: `core/skills/nodejs-nestjs/patterns.md`
- Safe-Pattern: `await dataSource.query("SELECT * FROM users WHERE email = $1", [email])`

### NST-005 — Prisma Raw Injection (`$queryRawUnsafe`)

- Source: `core/skills/nodejs-nestjs/patterns.md`
- Safe-Pattern: `await prisma.$queryRaw\`SELECT * FROM users WHERE id = ${id}\``

### NST-006 — Open Redirect in controller

- Source: `core/skills/nodejs-nestjs/patterns.md`
- Safe-Pattern: `const next = String(req.query.next

### NST-007 — Hardcoded secrets in source

- Source: `core/skills/nodejs-nestjs/patterns.md`
- Safe-Pattern: `const jwtSecret = process.env.JWT_SECRET`

### NST-008 — JWT verify without algorithm allowlist

- Source: `core/skills/nodejs-nestjs/patterns.md`
- Safe-Pattern: `jwt.verify(token, secret, { algorithms: ["HS256"] })`

### NST-009 — Missing body size limits

- Source: `core/skills/nodejs-nestjs/patterns.md`
- Safe-Pattern: `app.use(express.json({ limit: "1mb" }))`

### NST-010 — Verbose exception leak

- Source: `core/skills/nodejs-nestjs/patterns.md`
- Safe-Pattern: `catch (e) {`<br>`  logger.error(e)`<br>`  throw new HttpException("internal server error", 500)`<br>`}`

### NST-011 — Info leak in Swagger DTO

- Source: `core/skills/nodejs-nestjs/patterns.md`
- Safe-Pattern: `class UserDto {`<br>`  @ApiHideProperty()`<br>`  password: string`<br>`}`

### NST-012 — Unsafe implicit type conversion

- Source: `core/skills/nodejs-nestjs/patterns.md`
- Safe-Pattern: `app.useGlobalPipes(new ValidationPipe({ transform: false, whitelist: true, forbidNonWhitelisted: true }))`

### NST-013 — Raw HTML in template rendering

- Source: `core/skills/nodejs-nestjs/patterns.md`
- Safe-Pattern: `return res.render("page", { userContent })`<br>`...`<br>`{{ userContent }}`

### NST-014 — SSRF in `HttpService`

- Source: `core/skills/nodejs-nestjs/patterns.md`
- Safe-Pattern: `if (!ALLOWED_HOSTS.includes(hostname)) throw new ForbiddenException()`<br>`return this.httpService.get(url)`

### NST-015 — Missing rate limiting in root module

- Source: `core/skills/nodejs-nestjs/patterns.md`
- Safe-Pattern: `@Module({`<br>`  imports: [ThrottlerModule.forRoot([{ ttl: 60, limit: 20 }])],`<br>`})`<br>`app.useGlobalGuards(new ThrottlerGuard())`

### NST-016 — Insecure Reflector usage in Guard

- Source: `core/skills/nodejs-nestjs/patterns.md`
- Safe-Pattern: `const roles = this.reflector.getAllAndOverride("roles", [context.getHandler(), context.getClass()])`

### NST-017 — File upload without magic number check

- Source: `core/skills/nodejs-nestjs/patterns.md`
- Safe-Pattern: `const t = await fileTypeFromBuffer(file.buffer)`<br>`if (t?.mime !== "image/png") throw new BadRequestException()`

### NST-018 — Insecure bcrypt rounds

- Source: `core/skills/nodejs-nestjs/patterns.md`
- Safe-Pattern: `const hash = await bcrypt.hash(pass, 12)`<br>`...`<br>`const hash = await argon2.hash(pass)`

### NST-019 — XXE risk in xml2js parsing

- Source: `core/skills/nodejs-nestjs/patterns.md`
- Safe-Pattern: `await parseStringPromise(xmlData, { explicitCharkey: false })`<br>`...`<br>`// external entity processors disabled`

### NST-020 — Log Injection

- Source: `core/skills/nodejs-nestjs/patterns.md`
- Safe-Pattern: `const safe = userInput.replace(/[\\r\\n]/g, "_")`<br>`this.logger.log(safe)`

### PY-001 — FastAPI debug enabled in production

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Отключать debug в production и управлять через безопасный конфиг.

### PY-002 — Error detail leakage

- Source: `core/skills/domain-data-privacy/patterns.md`
- Safe-Pattern: Generic error response, детали только во внутренних логах.

### PY-003 — Unsafe pickle deserialization

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Использовать безопасные форматы (JSON/msgpack) и schema validation.

### PY-004 — Subprocess shell injection

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Использовать `shell=False`, whitelist аргументов и массив команд.

### PY-005 — YAML unsafe loader

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Использовать `yaml.safe_load` для недоверенных данных.

### PY-006 — Weak temp file handling

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Использовать `NamedTemporaryFile`/`mkstemp` с безопасными правами.

### PY-007 — SSRF via user URL fetch

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Host allowlist + blocking private ranges + egress policy.

### PY-008 — Missing request timeout in outgoing calls

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Всегда задавать timeout и retry budget.

### PY-009 — Hardcoded secret in code

- Source: `core/skills/domain-data-privacy/patterns.md`
- Safe-Pattern: Хранить секреты во внешнем Secret Manager/Vault.

### PY-010 — Insecure random for security tokens

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Использовать `secrets` module или `os.urandom`.

### PY-011 — JWT algorithm confusion

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Фиксированный список алгоритмов и строгая валидация claims.

### PY-012 — SQL injection in dynamic execute

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Parametrized queries / ORM bind params only.

### PY-013 — ORM mass assignment

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Использовать DTO/allowlist полей перед записью в модель.

### PY-014 — Path traversal in file operations

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: `abspath/resolve` + boundary check to base dir.

### PY-015 — eval/exec on untrusted data

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Запрет dynamic code execution, использовать safe parser.

### PY-016 — Insecure CORS wildcard with credentials

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Использовать строгий origin allowlist без wildcard+credentials.

### PY-017 — Missing rate limit on sensitive endpoints

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Добавлять rate limits/bruteforce protection на auth routes.

### PY-018 — Async endpoint with blocking I/O

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Использовать async clients (`httpx.AsyncClient`) и non-blocking I/O.

### PY-019 — Playwright launch with insecure flags

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Удалить insecure flags, использовать isolated runtime profile.

### PY-020 — FastAPI route without response_model returning DB object

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Задавать `response_model` и отделять ORM объекты от API DTO.

### PY-021 — SQLAlchemy text injection

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Использовать bind params и schema validation.

### PY-022 — Pydantic construct bypass for external input

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Для внешних данных использовать `model_validate`/`parse_obj` с validation.

### PY-023 — Playwright context isolation missing per session

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Создавать новый `browser.new_context()` для каждой сессии/tenant.

### PY-024 — Insecure httpx TLS config

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Запрещать `verify=False`, использовать trust store/pinning.

### PY-025 — Missing webhook signature check

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Проверять подпись и replay-window.

### PY-026 — Secrets in logs

- Source: `core/skills/domain-data-privacy/patterns.md`
- Safe-Pattern: Redaction policy и structured logging без секретов.

### PY-027 — Unbounded pagination/query limits

- Source: `core/skills/domain-platform-hardening/patterns.md`
- Safe-Pattern: Вводить max limits и server-side caps для pagination.

### PY-028 — Missing CSRF on state-changing form endpoints

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Включать CSRF protection для cookie-authenticated flows.

### PY-029 — Celery task deserialization risk

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Использовать json serializer и trusted broker controls.

### PY-030 — Unvalidated redirect target

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Проверять redirect allowlist и запрещать external arbitrary redirects.

### PY-100 — Fail-Open Auth (env token)

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Fail-closed: проверять `None`, валидировать секрет, использовать constant-time compare.

### PY-105 — BOLA in Django queryset

- Source: `core/skills/domain-access-management/patterns.md`
- Safe-Pattern: Ограничивать `queryset` по `request.user`/tenant policy.

### PY-110 — Media path traversal

- Source: `core/skills/domain-input-validation/patterns.md`
- Safe-Pattern: Нормализация + проверка префикса `MEDIA_ROOT`.

### RRC-001 — 152-ФЗ: PII в stdout / внешние логи

- Source: `core/skills/ru-regulatory/patterns.md`
- Safe-Pattern: Использовать редактирование/маскирование до логирования (например, `redact_email`, `redact_snils`), а также уровень логов без PII по умолчанию.

### RRC-002 — Data Residency: ПДн в зарубежные API без обезличивания

- Source: `core/skills/ru-regulatory/patterns.md`
- Safe-Pattern: Обезличить/агрегировать ПДн перед отправкой, отделить идентификаторы и payload, добавить контроль/аудит передачи данных.

### RRC-003 — GOST: небезопасные/несертифицированные крипто-библиотеки

- Source: `core/skills/ru-regulatory/patterns.md`
- Safe-Pattern: Использовать сертифицированные средства криптографии / GOST-совместимые библиотеки, соответствующие требованиям контура КИИ.

### RRC-004 — Import Substitution: hardcoded cloud metadata

- Source: `core/skills/ru-regulatory/patterns.md`
- Safe-Pattern: Уйти от hardcoded metadata: использовать абстракции конфигурации/переменные окружения и единый механизм discovery для целевого облака.

### RRC-005 — Foreign DNS/NTP

- Source: `core/skills/ru-regulatory/patterns.md`
- Safe-Pattern: Использовать российские или внутренние корпоративные DNS/NTP резолверы (например, `10.0.0.53`, `ntp.local`).

### RRC-006 — Insecure External Repositories

- Source: `core/skills/ru-regulatory/patterns.md`
- Safe-Pattern: В CI/CD разрешать только доверенные внутренние зеркала/репозитории артефактов (Nexus/Artifactory/internal registry).

### RRC-007 — Information Leakage in Errors

- Source: `core/skills/ru-regulatory/patterns.md`
- Safe-Pattern: Возвращать обобщенное сообщение пользователю; детали и stacktrace писать только во внутренние журналы.

### RRC-008 — Missing Security Audit

- Source: `core/skills/ru-regulatory/patterns.md`
- Safe-Pattern: Централизованно логировать неудачные входы, смену паролей и чувствительные события безопасности (SIEM/audit bus).

### RRC-009 — Unsigned binary execution

- Source: `core/skills/ru-regulatory/patterns.md`
- Safe-Pattern: Перед запуском проверять цифровую подпись/доверенную цепочку и хэш (особенно на критических узлах).

### RRC-010 — Insecure Data Deletion

- Source: `core/skills/ru-regulatory/patterns.md`
- Safe-Pattern: Перед удалением перезаписать файл нулями/случайными данными, затем удалить (`fsync` + `remove`) с учетом политики хранения.

### RRC-011 — Banned Functions (Security Policy)

- Source: `core/skills/ru-regulatory/patterns.md`
- Safe-Pattern: Использовать `subprocess.run([...], shell=False, check=True)` с фиксированным whitelist аргументов.

### RRC-012 — Missing Config Integrity Check

- Source: `core/skills/ru-regulatory/patterns.md`
- Safe-Pattern: Проверять SHA-256/HMAC целостность конфигурации при старте; при mismatch — fail closed и аудит-событие.

### RRC-013 — ГОСТ 57580.1 / ЦБ: "мясные" учетки вместо УДИ/УДА токенов

- Source: `core/skills/ru-regulatory/patterns.md`
- Safe-Pattern: Использовать токены УДИ/УДА (OIDC/OAuth2, client credentials, mTLS-bound tokens), запрет static user/pass в интеграциях и сервис-аккаунтах.

### RRC-014 — ЦБ: Недостаточная аутентификация интеграций (нет токен-ротации)

- Source: `core/skills/ru-regulatory/patterns.md`
- Safe-Pattern: Обязательная короткоживущая токен-модель, ротация, revoke/introspection, аудит выдачи и использования токенов.

### RRC-015 — FAPI.SEC/PAOK: запрет Implicit Flow, обязательный Code+PKCE+mTLS

- Source: `core/skills/ru-regulatory/patterns.md`
- Safe-Pattern: Использовать Authorization Code Flow + PKCE, а для межсервисного взаимодействия включать mTLS (client cert/key) и проверку FAPI-профиля.

### RRC-016 — Docker Root: запуск контейнера от root

- Source: `core/skills/ru-regulatory/patterns.md`
- Safe-Pattern: Явно создавать непривилегированного пользователя и переключаться на него (`RUN useradd -m appuser`, `USER appuser`).

### RRC-017 — Vault/ESO: запрет hardcoded Secret, требование ExternalSecret

- Source: `core/skills/ru-regulatory/patterns.md`
- Safe-Pattern: Использовать `kind: ExternalSecret` (ESO) + backend Vault; исключить plaintext секреты в Git/YAML.

### RRC-018 — Tech Stack: запрет drop-технологий в новых сервисах

- Source: `core/skills/ru-regulatory/patterns.md`
- Safe-Pattern: Для новых микросервисов использовать поддерживаемый стек (Python >= 3.10, без legacy PHP), фиксировать baseline в архитектурном стандарте.

### RRC-019 — Клинкер/Keycloak: обязательный auth middleware для внутренних API

- Source: `core/skills/ru-regulatory/patterns.md`
- Safe-Pattern: Все внутренние API должны проходить через middleware аутентификации Keycloak (`VerifyToken`/аналог), deny-by-default.

### RRC-020 — Целостность КИИ: контрольные суммы исполняемых файлов и конфигов перед стартом

- Source: `core/skills/ru-regulatory/patterns.md`
- Safe-Pattern: Перед запуском проверять SHA-256/ГОСТ-хэш исполняемого файла и критичных конфигов; при mismatch — fail closed и аудит-событие (Приказ 239).

### RRC-021 — СЗИ-контроль: отсутствие проверки состояния AV/IDS в контуре

- Source: `core/skills/ru-regulatory/patterns.md`
- Safe-Pattern: Перед запуском проверять наличие и работоспособность СЗИ (антивирус, IDS/IPS, EDR агент), логировать статус и блокировать старт при критическом отказе.

### RRC-022 — SDL/ГОСТ Р 56939: результаты статанализа не фиксируются в логах сборки

- Source: `core/skills/ru-regulatory/patterns.md`
- Safe-Pattern: Обязательная фиксация результатов SAST/SCA в артефактах CI (лог/отчет), подпись и хранение для аудита SDL по ГОСТ Р 56939.

### RRC-023 — Key Rotation: отсутствует `rotation_period` в Vault/KMS политиках

- Source: `core/skills/ru-regulatory/patterns.md`
- Safe-Pattern: Для криптографических ключей задать и контролировать `rotation_period`, автоматическую ротацию и журналировать события смены ключей.

### RRC-024 — Anti-Overlay/Integrity: нет CSP и контроля целостности UI

- Source: `core/skills/ru-regulatory/patterns.md`
- Safe-Pattern: Включить строгий CSP, SRI для внешних скриптов и проверки целостности DOM/critical forms для защиты ДБО от overlay/injection атак.

### RRC-025 — Payment Control: неизменность реквизитов между create и sign не контролируется

- Source: `core/skills/ru-regulatory/patterns.md`
- Safe-Pattern: Фиксировать hash реквизитов на этапе create и сравнивать перед sign/submit; при несовпадении — reject + audit event.

### RRC-026 — Post-Quantum Readiness: отсутствует стратегия крипто-миграции

- Source: `core/skills/ru-regulatory/patterns.md`
- Safe-Pattern: Вести инвентаризацию криптопримитивов, план гибридных схем и процедуру миграции ключей/сертификатов под PQ-ready профиль.

### RUBY-001 — Ruby Code Injection: `eval(params[:expr])`

- Source: `core/skills/ruby-rails/patterns.md`
- Safe-Pattern: `expr = params[:expr]`<br>`raise "invalid" unless expr =~ /\\A[0-9+\\-*\\/(). ]{1,64}\\z/`<br>`...`<br>`result = safe_math_eval(expr)`

### RUBY-002 — Command Injection: `system(params[:cmd])`

- Source: `core/skills/ruby-rails/patterns.md`
- Safe-Pattern: `action = params[:action]`<br>`allowed = { "uptime" => ["uptime"] }`<br>`raise "blocked" unless allowed.key?(action)`<br>`...`<br>`Open3.capture2e(*allowed[action])`

### RUBY-003 — Shell Injection: backticks with user input

- Source: `core/skills/ruby-rails/patterns.md`
- Safe-Pattern: `host = params[:host]`<br>`raise "invalid" unless host =~ /\\A[a-zA-Z0-9.-]{1,255}\\z/`<br>`...`<br>`out, _ = Open3.capture2e("ping", "-c", "1", host)`

### RUBY-004 — Unsafe Constantize: класс из params

- Source: `core/skills/ruby-rails/patterns.md`
- Safe-Pattern: `allow = { "HealthHandler" => HealthHandler }`<br>`key = params[:klass]`<br>`raise "blocked" unless allow.key?(key)`<br>`...`<br>`allow[key].new.call`

### RUBY-005 — Unsafe `send` from user method name

- Source: `core/skills/ruby-rails/patterns.md`
- Safe-Pattern: `method = params[:method]`<br>`allowed = %w[health status]`<br>`raise "blocked" unless allowed.include?(method)`<br>`...`<br>`service.public_send(method)`

### RUBY-006 — ERB Injection: шаблон из пользовательского ввода

- Source: `core/skills/ruby-rails/patterns.md`
- Safe-Pattern: `name = params[:template_name]`<br>`allowed = %w[welcome invoice]`<br>`raise "blocked" unless allowed.include?(name)`<br>`...`<br>`render template: "safe/#{name}"`

### RUBY-007 — SQL Fragment Injection: dynamic ORDER BY

- Source: `core/skills/ruby-rails/patterns.md`
- Safe-Pattern: `order = params[:order]`<br>`order = "name" unless %w[name created_at].include?(order)`<br>`...`<br>`User.order(order)`

### RUBY-008 — Unsafe YAML deserialization in command flow

- Source: `core/skills/ruby-rails/patterns.md`
- Safe-Pattern: `blob = params[:blob]`<br>`...`<br>`obj = YAML.safe_load(blob, permitted_classes: [], aliases: false)`

### RUBY-009 — Mass Assignment: критичные поля принимаются напрямую из params

- Source: `core/skills/ruby-rails/patterns.md`
- Safe-Pattern: `allowed = params.require(:user).permit(:email, :display_name)`<br>`user.update(allowed)`

### RUBY-010 — Unsafe Render Path: путь шаблона из пользовательского ввода

- Source: `core/skills/ruby-rails/patterns.md`
- Safe-Pattern: `name = params[:name]`<br>`raise "blocked" unless %w[home about].include?(name)`<br>`render template: "pages/#{name}"`

### RUBY-011 — YAML.load Deserialization: небезопасная загрузка объектов

- Source: `core/skills/ruby-rails/patterns.md`
- Safe-Pattern: `obj = YAML.safe_load(params[:payload], permitted_classes: [], aliases: false)`

### RUBY-012 — Command Injection через backticks

- Source: `core/skills/ruby-rails/patterns.md`
- Safe-Pattern: `allowed = {"uptime" => ["uptime"]}`<br>`cmd = params[:action]`<br>`raise "blocked" unless allowed.key?(cmd)`<br>`Open3.capture2e(*allowed[cmd])`

### RUBY-013 — Open Redirect в контроллере

- Source: `core/skills/ruby-rails/patterns.md`
- Safe-Pattern: `next_url = params[:next]`<br>`next_url = root_path unless next_url&.start_with?("/")`<br>`redirect_to next_url`

### RUBY-014 — Insecure Cookies: отсутствие HttpOnly/Secure

- Source: `core/skills/ruby-rails/patterns.md`
- Safe-Pattern: `cookies[:session] = { value: token, httponly: true, secure: true, same_site: :strict }`

### RUBY-015 — Hardcoded Secret in initializer

- Source: `core/skills/ruby-rails/patterns.md`
- Safe-Pattern: `JWT_SECRET = ENV.fetch("JWT_SECRET")`

### RUBY-016 — Weak Crypto Digest (MD5/SHA1)

- Source: `core/skills/ruby-rails/patterns.md`
- Safe-Pattern: `Digest::SHA256.hexdigest(password + salt)`

### RUBY-017 — SSRF через Net::HTTP на URL из params

- Source: `core/skills/ruby-rails/patterns.md`
- Safe-Pattern: `uri = URI(params[:url])`<br>`raise "blocked" unless ALLOWED_HOSTS.include?(uri.host)`<br>`Net::HTTP.get(uri)`

### RUBY-018 — Unsafe Constantize from params

- Source: `core/skills/ruby-rails/patterns.md`
- Safe-Pattern: `allow = {"ReportJob" => ReportJob}`<br>`klass = allow.fetch(params[:klass])`

### RUBY-019 — Debug endpoint in production

- Source: `core/skills/ruby-rails/patterns.md`
- Safe-Pattern: `if Rails.env.development?`<br>`  get "/debug/env", to: "debug#env"`<br>`end`

### RUBY-020 — Sensitive error leakage наружу

- Source: `core/skills/ruby-rails/patterns.md`
- Safe-Pattern: `Rails.logger.error(e.full_message)`<br>`render json: { error: "internal server error" }, status: 500`

### SEC-001 — SSRF to Cloud Metadata API

- Source: `core/skills/cloud-secrets/patterns.md`
- Safe-Pattern: Блокировать link-local metadata endpoints в egress policy; использовать IMDSv2/metadata proxy с явной авторизацией.

### SEC-002 — K8s Secret in ConfigMap

- Source: `core/skills/cloud-secrets/patterns.md`
- Safe-Pattern: Хранить секреты только в `Secret`/external secrets manager (Vault/KMS), шифровать at-rest и ограничить RBAC.

### SEC-003 — Privileged Container

- Source: `core/skills/cloud-secrets/patterns.md`
- Safe-Pattern: `privileged: false`, `allowPrivilegeEscalation: false`, `runAsNonRoot: true`, минимальные capabilities.

### SEC-004 — HostPath Mount of Sensitive Paths

- Source: `core/skills/cloud-secrets/patterns.md`
- Safe-Pattern: Запретить опасные `hostPath` mounts; использовать CSI/ephemeral volumes с ограниченными правами.

### SEC-005 — Service Account Token Auto-Mount

- Source: `core/skills/cloud-secrets/patterns.md`
- Safe-Pattern: Отключить auto-mount по умолчанию; выдавать токен только workload-ам, которым он необходим.

### SEC-006 — ENV Secret Leakage to Logs

- Source: `core/skills/cloud-secrets/patterns.md`
- Safe-Pattern: Никогда не логировать весь ENV; применять allowlist полей и redaction для секретов.

### SEC-007 — Hardcoded Cloud Credentials

- Source: `core/skills/cloud-secrets/patterns.md`
- Safe-Pattern: Использовать workload identity / IAM role / short-lived STS tokens без hardcode.

### SEC-008 — Insecure JWT Validation

- Source: `core/skills/cloud-secrets/patterns.md`
- Safe-Pattern: Проверять подпись, `issuer`, `audience`, `exp`, `nbf`, `alg` allowlist.

### SEC-009 — Vault Token in Plain Config

- Source: `core/skills/cloud-secrets/patterns.md`
- Safe-Pattern: Хранить Vault auth через AppRole/K8s auth + short-lived token, ротацию и scoped policies; обязательно использовать Vault Agent Injector для автоматической доставки и ротации токенов/секретов в workload.

### SEC-010 — Vault TLS Verification Disabled

- Source: `core/skills/cloud-secrets/patterns.md`
- Safe-Pattern: Всегда `verify=True`, mTLS/CA pinning, запрет insecure transport.

### SEC-011 — Unencrypted Secret in Object Storage

- Source: `core/skills/cloud-secrets/patterns.md`
- Safe-Pattern: Включить SSE-KMS/CMK, ограничить доступ bucket policy и включить audit trail.

### SEC-012 — Broad KMS Permissions

- Source: `core/skills/cloud-secrets/patterns.md`
- Safe-Pattern: Принцип least privilege: ограничить actions/resources и контекст ключей.

### SEC-013 — Publicly Exposed Secrets Endpoint

- Source: `core/skills/cloud-secrets/patterns.md`
- Safe-Pattern: Удалить/закрыть debug endpoints, включить authz + environment gating для non-prod only.

### SEC-014 — Missing Secret Rotation Policy

- Source: `core/skills/cloud-secrets/patterns.md`
- Safe-Pattern: Обязательная ротация секретов/ключей (TTL), автоматизация revoke/renew и контроль просрочки.

### SEC-015 — Unsafe Secret in CI Variables

- Source: `core/skills/cloud-secrets/patterns.md`
- Safe-Pattern: Masked/protected CI variables, secret scanning в pipeline, запрет echo/print секретов.

### SEC-016 — External Secrets Operator Required

- Source: `core/skills/cloud-secrets/patterns.md`
- Safe-Pattern: Использовать `kind: ExternalSecret`, ссылающийся на `SecretStore/ClusterSecretStore` (Vault backend), и исключить хранение секретов в Git.

### SEC-017 — Trusted Mounts for DB Passwords

- Source: `core/skills/cloud-secrets/patterns.md`
- Safe-Pattern: Передавать секреты как файлы через `volumeMounts` (Vault Agent Injector или ESO synced volume), читать пароль из файловой системы, а не из ENV.

### SQD-001 — Squid allows all clients

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `http_access deny all`<br>`http_access allow localnet`

### SQD-002 — Squid cache_peer uses plaintext HTTP

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `cache_peer upstream.example parent 3129 0 no-query tls`

### SQD-003 — ssl_bump without certificate validation policy

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `sslproxy_cert_error deny all`

### SQD-004 — Weak ACL for CONNECT methods

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `acl SSL_ports port 443`

### SQD-005 — No request rate/connection controls

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `maxconn 100`

### SQD-006 — Access logs disabled

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `access_log stdio:/var/log/squid/access.log`

### SQD-007 — Unsafe refresh_pattern wildcard

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `refresh_pattern -i \\.(html

### SQD-008 — DNS over insecure resolver

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `dns_nameservers 10.0.0.53`

### SQD-009 — Proxy auth not required for sensitive egress

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd`

### SQD-010 — No domain allowlist on egress

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `acl allowed_domains dstdomain .corp.local`<br>`http_access allow allowed_domains`

### SQD-011 — Unsafe forwarded_for policy

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `forwarded_for transparent`

### SQD-012 — Insecure cache_dir permissions

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `cache_effective_user squid`<br>`cache_effective_group squid`

### SQD-013 — No denylist for metadata endpoints

- Source: `core/skills/infra-k8s-helm/patterns.md`
- Safe-Pattern: `acl cloud_meta dst 169.254.169.254/32`<br>`http_access deny cloud_meta`

---
Total sections: 550
Empty sections detected: 0
Final artifact status: ready for Git publication.
