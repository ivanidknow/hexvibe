# Auth / Keycloak / OIDC

## Stack overview

**OAuth2/OIDC** clients, **JWT** validation, **Keycloak** integration, token exchange, and browser-flow hardening. Metrics are prefixed **`AK`**.

## Top threats

- Algorithm confusion and weak JWT validation (`AK-001`, `AK-002`, `AK-008`, `AK-016`).
- Redirect and session fixation (`AK-004`, `AK-006`, `AK-015`, `AK-016`).
- Secret handling and token forwarding (`AK-005`, `AK-007`, `AK-011`–`AK-014`).
- PKCE, DPoP, and operational abuse (`AK-009`, `AK-010`, `AK-012`).

## Pattern catalog

Complete Anti-Pattern / Safe-Pattern definitions live in [`patterns.md`](patterns.md). The table below is a **table of contents** by metric ID.

| ID | Metric | Stack |
|---|---|---|
| `AK-001` | Weak Algorithm: разрешен `alg=none` или нефиксированный алгоритм | `from jose import jwt` `header = jwt.get_unverified_header(token)` `if header.get(\"alg\") not in {\"RS256\", \"ES256\", \"GOST3410\"}:` `    raise ValueError(\"unsupported alg\")` `claims = jwt.decode(` `    token,` `    jwk,` `    algorithms=[\"RS256\", \"ES256\", \"GOST3410\"],` `    issuer=issuer_url,` `    audience=client_id,` `    options={\"verify_signature\": True},` `)` `# для контура Клинкера включить профиль российских криптоалгоритмов (ГОСТ)` |
| `AK-002` | Issuer/Audience Mismatch: невалидируемые `iss` и `aud` | `import jwt` `claims = jwt.decode(` `    token,` `    pub_key,` `    algorithms=[\"RS256\", \"ES256\"],` `    issuer=issuer_url,` `    audience=client_id,` `    options={\"verify_signature\": True, \"verify_exp\": True, \"verify_nbf\": True, \"verify_iat\": True},` `)` |
| `AK-003` | JWS Header Injection: прямое доверие `kid` из заголовка | `header = jwt.get_unverified_header(token)` `kid = header.get(\"kid\")` `trusted_kids = {k[\"kid\"] for k in jwks[\"keys\"]}` `if kid not in trusted_kids:` `    raise ValueError(\"untrusted kid\")` `jwk = next(k for k in jwks[\"keys\"] if k[\"kid\"] == kid)` `claims = jwt.decode(token, jwk, algorithms=[\"RS256\", \"ES256\"], issuer=issuer_url, audience=client_id)` |
| `AK-004` | Insecure Redirects: wildcard и нет точного HTTPS-match | `allowed_redirects = {` `    \"https://app.example.com/oidc/callback\",` `    \"https://admin.example.com/oidc/callback\",` `}` `if redirect_uri not in allowed_redirects:` `    raise ValueError(\"redirect_uri mismatch\")` |
| `AK-005` | Client Secret Exposure: secret захардкожен в коде | `import os` `from keycloak import KeycloakOpenID` `kc = KeycloakOpenID(` `    server_url=os.environ[\"KEYCLOAK_URL\"],` `    realm_name=os.environ[\"KEYCLOAK_REALM\"],` `    client_id=os.environ[\"KEYCLOAK_CLIENT_ID\"],` `    client_secret_key=os.environ[\"KEYCLOAK_CLIENT_SECRET\"],` `)` |
| `AK-006` | Subject Confusion: `sub` не связан с текущим пользователем | `claims = jwt.decode(token, jwk, algorithms=[\"RS256\", \"ES256\"], issuer=issuer_url, audience=client_id, options={\"verify_exp\": True, \"verify_nbf\": True, \"verify_iat\": True})` `user = db.get_user_by_id(current_user_id)` `if claims.get(\"sub\") != user.oidc_sub:` `    raise ValueError(\"subject mismatch\")` |
| `AK-007` | Authorization Code не привязан к `redirect_uri` и `client_id` | `assert request_client_id == stored_client_id_for_code(code)` `assert request_redirect_uri == stored_redirect_uri_for_code(code)` `token = exchange_code_for_token(code=code, client_id=request_client_id, redirect_uri=request_redirect_uri)` |
| `AK-008` | Нет обязательной проверки времени жизни токена (`exp/nbf/iat`) | `claims = jwt.decode(token, jwk, algorithms=[\"RS256\", \"ES256\"], issuer=issuer_url, audience=client_id, options={\"verify_exp\": True, \"verify_nbf\": True, \"verify_iat\": True})` |
| `AK-009` | PKCE Enforcement: Authorization Code Flow без `code_challenge`/`code_verifier` | `auth_url = f"{issuer}/protocol/openid-connect/auth?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}&code_challenge={code_challenge}&code_challenge_method=S256"` `token = exchange_code(code=code, code_verifier=code_verifier)` `if not code_verifier:` `    raise ValueError("pkce required")` |
| `AK-010` | DPoP отсутствует для высокорисковых операций (Token Theft risk) | `def call_high_risk_api(access_token: str, dpop_proof: str):` `    if not dpop_proof:` `        raise ValueError("DPoP proof required")` `    return client.post("/payments/transfer", headers={"Authorization": f"Bearer {access_token}", "DPoP": dpop_proof})` `# DPoP обязателен для высокорисковых операций ЦБ, чтобы снизить риск кражи токенов` |
| `AK-011` | PII in JWT: конфиденциальные данные в открытом payload | `payload = {"sub": user_id, "role": role, "scope": "api.read"}` `token = jwt.encode(payload, private_key, algorithm="RS256")` `# PII moved to userinfo endpoint or encrypted storage` |
| `AK-012` | JWKS Rate Limiting: нет ограничений на запросы к `/.well-known/jwks.json` при неизвестн... | `def get_jwk_for_kid(kid: str):` `    if kid in negative_kid_cache and not negative_kid_cache[kid].expired:` `        raise ValueError("unknown kid cached")` `    if not jwks_rate_limiter.allow("jwks_fetch"):` `        raise RuntimeError("jwks rate limit exceeded")` `    jwks = requests.get(f"{issuer}/.well-known/jwks.json", timeout=2).json()` `    # cache keys and unknown kid misses` `    return select_key_from_jwks(jwks, kid)` |
| `AK-013` | Insecure Token Forwarding: прямой проброс пользовательского JWT между микросервисами | `def exchange_token(user_jwt: str, audience: str) -> str:` `    resp = requests.post(f"{issuer}/protocol/openid-connect/token", data={` `        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",` `        "subject_token": user_jwt,` `        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",` `        "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",` `        "audience": audience,` `    }, auth=(client_id, client_secret), cert=(client_cert_path, client_key_path), timeout=5)` `    resp.raise_for_status()` `    return resp.json()["access_token"]`  `def call_internal_service(user_jwt: str):` `    svc_token = exchange_token(user_jwt, audience="orders-api")` `    return requests.get("http://orders.internal/api/orders", headers={"Authorization": f"Bearer {svc_token}"}, timeout=5)` `# token exchange endpoint /token вызывать только по mTLS в профиле ФАПИ.ПАОК` |
| `AK-014` | Missing Resource Indicators: отсутствует параметр `resource` при запросе токена | `token_req = {` `    "grant_type": "authorization_code",` `    "code": code,` `    "redirect_uri": redirect_uri,` `    "resource": "https://api.example.com/orders",` `}` `token = requests.post(token_url, data=token_req, auth=(client_id, client_secret), timeout=5)` `token.raise_for_status()` |
| `AK-015` | OIDC State Validation Missing: callback не проверяет `state` | `@app.get("/oidc/callback")` `async def callback(code: str, state: str, request: Request):` `    expected = request.session.get("oidc_state")` `    if not expected or state != expected:` `        raise HTTPException(status_code=401, detail="invalid state")` `    ...` `    return await exchange_code(code)` |
| `AK-016` | OIDC Nonce Validation Missing: ID Token принимается без проверки `nonce` | `id_claims = jwt.decode(id_token, jwk, algorithms=["RS256","ES256"], audience=client_id, issuer=issuer)` `expected_nonce = request.session.get("oidc_nonce")` `if not expected_nonce or id_claims.get("nonce") != expected_nonce:` `    raise HTTPException(status_code=401, detail="invalid nonce")` `...` `return id_claims` |
| `AK-017` | Session Management: нет принудительного logout и refresh_token TTL > 24ч | `refresh_token_ttl = 86400` `if refresh_token_ttl > 86400:` `    raise ValueError("CB session limit exceeded")` `enable_backchannel_logout = True` `enable_frontchannel_logout = True` `revoke_refresh_token_on_logout = True` |
| `AK-018` | Zero Trust mTLS: межсервисные вызовы выполняются без mTLS | Все межсервисные вызовы выполнять по mTLS (service identity, cert pinning, trust policy), не только token exchange endpoint. |
| `AK-019` | ASVS L3 Admin Session: отсутствует ротация секретов и ограничение админ-сессий | Для админ-учетных записей принудительная ротация клиентских секретов, короткий TTL сессий, step-up auth и немедленный revoke при logout/risk events. |
| `AK-020` | jose.jwt.decode with `verify_signature=False` | Никогда не отключать проверку подписи; валидировать подпись JWT по JWKS и reject токены с invalid signature. |
| `AK-021` | jose.jwt.decode without explicit algorithms allowlist | Всегда указывать `algorithms=["RS256"]` (или строгий allowlist) и запрещать algorithm confusion/fallback. |

## Verification

**Verification:** Check the gold testbed file(s) below for `Vulnerable: <ID>` markers (static Semgrep + `detection-matrix.md` ground truth).

- [`gold-standard-testbed/api_vulnerable.py`](../gold-standard-testbed/api_vulnerable.py)

**Optional HTTP integration tests** (pytest + httpx; require a running API, `HEXVIBE_TARGET_URL`): [`gold-standard-testbed/integration/verify_auth_keycloak_poc.py`](../gold-standard-testbed/integration/verify_auth_keycloak_poc.py). See [`gold-standard-testbed/integration/README.md`](../gold-standard-testbed/integration/README.md).

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

