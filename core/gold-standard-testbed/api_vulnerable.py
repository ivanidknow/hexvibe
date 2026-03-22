"""
Intentionally vulnerable training corpus.
Do NOT deploy to production.
"""

import os
import pickle
import subprocess
import traceback
from base64 import b64decode
from datetime import datetime, timedelta, timezone

import httpx
import jwt
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, UploadFile
from jose import jwt as jose_jwt
from pydantic import BaseModel
from slowapi import Limiter

app = FastAPI(title="HexVibe Vulnerable API")
limiter = Limiter(key_func=lambda request: "global")


# Vulnerable: AK-001 (Weak Algorithm)
def ak_001_decode(token: str):
    return jose_jwt.decode(token, key="", algorithms=["none"])


# Vulnerable: AK-002 (Issuer/Audience Mismatch)
def ak_002_decode(token: str, pub_key: str):
    return jwt.decode(token, pub_key, algorithms=["RS256"], options={"verify_signature": True})


# Vulnerable: AK-003 (JWS Header Injection)
def ak_003_decode(token: str, jwks: dict):
    header = jose_jwt.get_unverified_header(token)
    jwk = jwks[header["kid"]]
    return jose_jwt.decode(token, jwk, algorithms=["RS256"])


# Vulnerable: AK-004 (Insecure Redirects)
allowed_redirects = ["https://app.example.com/*", "http://localhost/*"]


# Vulnerable: AK-005 (Client Secret Exposure)
KEYCLOAK_CLIENT_SECRET = "hardcoded-secret"


# Vulnerable: AK-006 (Subject Confusion)
def ak_006_user_lookup(claims: dict):
    return {"user_by_email": claims.get("email")}


# Vulnerable: AK-007 (Auth Code not bound to redirect/client)
def ak_007_exchange(code: str, client_id: str):
    return {"token": f"code={code}&client={client_id}"}


# Vulnerable: AK-008 (Missing exp/nbf/iat verification)
def ak_008_decode(token: str, jwk: dict, issuer_url: str, client_id: str):
    return jose_jwt.decode(
        token,
        jwk,
        algorithms=["RS256"],
        issuer=issuer_url,
        audience=client_id,
        options={"verify_exp": False, "verify_nbf": False, "verify_iat": False},
    )


# Vulnerable: AK-009 (PKCE Enforcement missing)
def ak_009_auth_url(issuer: str, client_id: str, redirect_uri: str) -> str:
    return f"{issuer}/protocol/openid-connect/auth?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}"


# Vulnerable: AK-010 (No DPoP on high-risk op)
def ak_010_high_risk_call(access_token: str):
    return {"Authorization": f"Bearer {access_token}"}


# Vulnerable: AK-011 (PII in JWT)
def ak_011_issue_token(user_id: str, email: str, phone: str, full_name: str, role: str, private_key: str):
    payload = {"sub": user_id, "email": email, "phone": phone, "name": full_name, "role": role}
    return jwt.encode(payload, private_key, algorithm="RS256")


# Vulnerable: AK-012 (No JWKS rate limiting on unknown kid)
def ak_012_fetch_jwks(issuer: str):
    return httpx.get(f"{issuer}/.well-known/jwks.json").json()


# Vulnerable: AK-013 (Insecure Token Forwarding)
def ak_013_forward_user_jwt(user_jwt: str):
    return httpx.get("http://orders.internal/api/orders", headers={"Authorization": f"Bearer {user_jwt}"})


# Vulnerable: AK-014 (Missing Resource Indicators)
def ak_014_token_request(code: str, redirect_uri: str):
    return {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri}


# Vulnerable: AK-015 (OIDC State Validation Missing)
@app.get("/ak015/oidc/callback")
async def ak015_callback(code: str, state: str):
    return {"code": code, "state": state}


# Vulnerable: AK-016 (OIDC Nonce Validation Missing)
def ak016_decode_id_token(id_token: str, jwk: dict, client_id: str, issuer: str):
    return jwt.decode(id_token, jwk, algorithms=["RS256"], audience=client_id, issuer=issuer)


# Vulnerable: AK-017 (Session management: missing forced logout and long refresh TTL)
refresh_token_ttl = 864000
enable_backchannel_logout = False

# Vulnerable: AK-018 (No mTLS for inter-service calls)
orders = httpx.get("http://orders.internal/api")

# Vulnerable: AK-019 (No admin secret rotation / long admin sessions)
admin_session_ttl = 7 * 24 * 3600
admin_client_secret = "static-secret"


# Vulnerable: FAS-001 (SlowAPI decorator order)
@limiter.limit("2/minute")
@app.get("/fas001")
async def fas001(request: Request):
    return {"ok": True}


# Vulnerable: FAS-002 (Limited endpoint without request arg)
@app.get("/fas002")
@limiter.limit("5/minute")
async def fas002():
    return {"status": "ok"}


# Vulnerable: FAS-003 (No response object where needed)
@app.get("/fas003")
@limiter.limit("5/minute")
async def fas003(request: Request):
    return {"key": "value"}


# Vulnerable: FAS-004 (SQLi f-string)
def fas004_query(name: str, score: int) -> str:
    return f"INSERT INTO HighScores(name, score) VALUES ('{name}', {score})"


# Vulnerable: FAS-005 (SQLi string concatenation)
def fas005_query(name: str, score: int) -> str:
    return "INSERT INTO HighScores(name, score) VALUES ('" + name + "', " + str(score) + ")"


# Vulnerable: FAS-006 (Transaction leak)
async def fas006_non_atomic(db):
    await db.execute("UPDATE wallets SET amount=amount-10 WHERE id=1")
    await db.execute("UPDATE wallets SET amount=amount+10 WHERE id=2")


# Vulnerable: FAS-007 (Missing await)
async def fas007_missing_await(db):
    db.execute("SELECT 1")


# Vulnerable: FAS-008 (Client created per request)
@app.get("/fas008/proxy")
async def fas008_proxy(url: str):
    async with httpx.AsyncClient() as client:
        r = await client.get(url)
    return {"status": r.status_code}


# Vulnerable: FAS-009 (Missing timeout)
async def fas009_no_timeout():
    async with httpx.AsyncClient() as client:
        return await client.get("https://api.example.internal/data")


# Vulnerable: FAS-010 (PII leakage in logs)
@app.post("/fas010/login")
async def fas010_login(request: Request):
    body = await request.json()
    print(f"raw_request={request} body={body}")
    return {"ok": True}


# Vulnerable: FAS-011 (Exposed docs in prod)
fas011_app = FastAPI(title="Exposed Docs API")


# Vulnerable: FAS-012 (Insecure CORS wildcard)
fas012_cors_config = {"allow_origins": ["*"], "allow_credentials": True}


# Vulnerable: FAS-013 (Pydantic arbitrary types)
class FAS013RawModel(BaseModel):
    dangerous: object

    class Config:
        arbitrary_types_allowed = True


# Vulnerable: FAS-014 (Background task without exception handling)
def fas014_send_email_task(email: str, payload: dict):
    raise RuntimeError(f"SMTP failure for {email} with payload {payload}")


@app.post("/fas014/notify")
async def fas014_notify(background_tasks: BackgroundTasks):
    background_tasks.add_task(fas014_send_email_task, "user@example.com", {"status": "ok"})
    return {"queued": True}


# Vulnerable: FAS-015 (Large payload DoS)
@app.post("/fas015/upload")
async def fas015_upload(file: UploadFile):
    data = await file.read()
    return {"size": len(data)}


# Vulnerable: FAS-016 (Host/Header injection)
@app.get("/fas016/tenant")
async def fas016_tenant(request: Request):
    tenant = request.headers.get("x-tenant-id", "")
    callback = f"https://{request.headers.get('host', '')}/cb/{tenant}"
    return {"callback": callback}


# Vulnerable: FAS-017 (Mass assignment)
class FAS017UserUpdate(BaseModel):
    email: str
    is_admin: bool = False
    balance: int = 0


@app.patch("/fas017/users/{user_id}")
async def fas017_patch_user(user_id: int, dto: FAS017UserUpdate):
    return {"user_id": user_id, "payload": dto.model_dump()}


# Vulnerable: FAS-018 (Insecure file upload path traversal)
@app.post("/fas018/files")
async def fas018_file_upload(file: UploadFile):
    path = f"/data/uploads/{file.filename}"
    content = await file.read()
    return {"path": path, "bytes": len(content)}


# Vulnerable: FAS-019 (Verbose error messages)
@app.get("/fas019/orders/{order_id}")
async def fas019_get_order(order_id: int):
    try:
        raise RuntimeError("DB connection secret=postgres://admin:pass@db")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# Vulnerable: FAS-020 (Async context leakage)
async def fas020_get_db():
    session = object()
    yield session


# Vulnerable: FAS-021 (OS Command Injection)
@app.get("/fas021/diag")
async def fas021_diag(host: str):
    subprocess.run(f"nslookup {host}", shell=True, check=False)
    return {"host": host}


# Vulnerable: FAS-022 (Unsafe Deserialization)
@app.post("/fas022/import")
async def fas022_import(payload: str):
    obj = pickle.loads(b64decode(payload))
    return {"loaded_type": str(type(obj))}


# Vulnerable: FAS-023 (CSRF on Cookie Session)
@app.post("/fas023/users/me/email")
async def fas023_change_email(req: dict, request: Request):
    session_id = request.cookies.get("session_id")
    return {"session_id": session_id, "email": req.get("email")}


# Vulnerable: FAS-024 (SSTI via user template)
@app.post("/fas024/render")
async def fas024_render(tpl: str, ctx: dict):
    rendered = tpl
    for k, v in ctx.items():
        rendered = rendered.replace(f"{{{{{k}}}}}", str(v))
    return {"rendered": rendered}


# Vulnerable: FAS-025 (Code Injection via eval/exec)
@app.post("/fas025/calc")
async def fas025_calc(user_input: str):
    result = eval(user_input)
    exec(user_input)
    return {"result": str(result)}


# Vulnerable: FAS-026 (Command Injection via os.system/subprocess shell=True)
@app.post("/fas026/ops/run")
async def fas026_run(cmd: str):
    os.system(cmd)
    subprocess.run(cmd, shell=True, check=False)
    return {"cmd": cmd}


# Vulnerable: FAS-027 (Unsafe dynamic import)
@app.get("/fas027/plugin")
async def fas027_plugin(mod: str):
    m = __import__(mod)
    return {"module": str(m)}


# Vulnerable: BIZ-001 (BOLA by object id)
@app.get("/biz001/orders/{order_id}")
async def biz001_get_order(order_id: int):
    return {"order_id": order_id, "owner_id": 42}


# Vulnerable: BIZ-002 (Trust user_id from request)
@app.get("/biz002/profile")
async def biz002_profile(user_id: int):
    return {"profile_for": user_id}


# Vulnerable: BIZ-003 (BOPLA mass update protected fields)
class BIZ003AccountUpdate(BaseModel):
    email: str
    is_admin: bool = False
    balance: int = 0


@app.patch("/biz003/accounts/{account_id}")
async def biz003_patch_account(account_id: int, dto: BIZ003AccountUpdate):
    return {"account_id": account_id, "updated": dto.model_dump()}


# Vulnerable: BIZ-004 (Vertical privilege escalation via role field)
@app.post("/biz004/admin/promote")
async def biz004_promote(dto: dict):
    return {"user_id": dto.get("user_id"), "role": dto.get("role")}


# Vulnerable: BIZ-005 (MFA bypass)
@app.post("/biz005/payments/{payment_id}/confirm")
async def biz005_confirm(payment_id: int):
    return {"payment_id": payment_id, "confirmed": True}


# Vulnerable: BIZ-006 (Missing challenge binding in MFA verify)
@app.post("/biz006/mfa/verify")
async def biz006_verify(code: str):
    return {"ok": code == "123456"}


# Vulnerable: BIZ-007 (Broken workflow transition)
@app.post("/biz007/orders/{order_id}/pay")
async def biz007_pay(order_id: int):
    return {"order_id": order_id, "status": "paid"}


# Vulnerable: BIZ-008 (Replay without idempotency key)
@app.post("/biz008/transfers")
async def biz008_transfer(req: dict):
    return {"transfer": req}


# Vulnerable: BIZ-009 (Tenant breakout, no tenant scope)
@app.get("/biz009/invoices/{invoice_id}")
async def biz009_invoice(invoice_id: int):
    return {"invoice_id": invoice_id, "tenant_id": "another-tenant"}


# Vulnerable: BIZ-010 (Sensitive action without re-auth)
@app.post("/biz010/users/me/change-email")
async def biz010_change_email(req: dict):
    return {"new_email": req.get("new_email")}


# Vulnerable: BIZ-011 (Business SSRF)
@app.post("/biz011/preview")
async def biz011_preview(dto: dict):
    async with httpx.AsyncClient() as client:
        r = await client.get(dto["url"])
    return {"status": r.status_code}


# Vulnerable: BIZ-012 (Blind trust in internal service)
@app.get("/biz012/risk/{user_id}")
async def biz012_risk(user_id: int):
    async with httpx.AsyncClient(timeout=5.0) as client:
        r = await client.get(f"http://risk.internal/score/{user_id}")
    return {"allow_transfer": r.json().get("allow_transfer")}


# Vulnerable: BIZ-013 (Shadow API exposure)
@app.get("/debug/sql")
async def biz013_debug_sql():
    return {"dsn": os.getenv("DATABASE_URL")}


# Vulnerable: BIZ-014 (Race Condition / Non-Atomic Financial Operations)
@app.post("/biz014/wallet/transfer")
async def biz014_transfer(req: dict):
    src_balance = req["src_balance"] - req["amount"]
    dst_balance = req["dst_balance"] + req["amount"]
    return {"src_balance": src_balance, "dst_balance": dst_balance}


# Vulnerable: BIZ-015 (HTTP Parameter Pollution)
@app.get("/biz015/search")
async def biz015_search(role: str = "user"):
    return {"role": role}


# Vulnerable: BIZ-016 (Unrestricted export size)
@app.get("/biz016/exports/orders.csv")
async def biz016_export_orders(limit: int = 1000000):
    return {"limit": limit}


# Vulnerable: BIZ-017 (CSV formula injection)
def biz017_row_to_csv(user: dict) -> list[str]:
    return [user["name"], user["email"], user["comment"]]


# Vulnerable: BIZ-018 (Trusting client-side calculations)
@app.post("/biz018/checkout")
async def biz018_checkout(payload: dict):
    order_total = payload["client_total"]
    discount = payload.get("discount", 0)
    return {"charged": order_total - discount}


# Vulnerable: BIZ-019 (Missing webhook signature verification)
@app.post("/biz019/webhook/payment")
async def biz019_payment_webhook(payload: dict):
    return {"order_id": payload.get("order_id"), "status": "paid"}


# Vulnerable: LOG-001 (Silent exception)
async def log001_save_event(repo, event):
    try:
        await repo.save(event)
    except Exception:
        pass


# Vulnerable: LOG-002 (Missing trace-id in logs)
def log002_no_trace_logging():
    print("request accepted")


# Vulnerable: LOG-003 (Unstructured security log)
def log003_unstructured(username: str):
    print(f"login failed for {username}")


# Vulnerable: LOG-004 (PII leakage in logs)
def log004_log_payload(payload: dict):
    print(f"auth payload={payload}")


# Vulnerable: LOG-005 (Stack trace to client)
@app.get("/log005/error")
async def log005_error():
    try:
        raise RuntimeError("boom")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=traceback.format_exc()) from exc


# Vulnerable: LOG-006 (No audit event for role change)
@app.post("/log006/admin/users/{uid}/role")
async def log006_set_role(uid: int, role: str):
    return {"uid": uid, "role": role}


# Vulnerable: LOG-007 (Missing failed-auth telemetry)
@app.post("/log007/login")
async def log007_login(auth_ok: bool):
    if not auth_ok:
        raise HTTPException(status_code=401, detail="invalid credentials")
    return {"ok": True}


# Vulnerable: LOG-008 (No latency telemetry in middleware)
@app.middleware("http")
async def log008_middleware(request: Request, call_next):
    return await call_next(request)


# Vulnerable: LOG-009 (No integrity/immutability controls)
async def log009_audit_write(audit_log, pid: int):
    await audit_log.write({"event": "payment_approved", "id": pid})


# Vulnerable: LOG-010 (No centralized exception sanitizer)
@app.get("/log010/x")
async def log010_x():
    raise RuntimeError("db password is wrong: secret=...")


# Vulnerable: LOG-011 (Log injection)
@app.get("/log011/search")
async def log011_search(q: str):
    print(f"search query={q}")
    return {"ok": True}


# Vulnerable: LOG-012 (Sensitive locals in exception context)
def log012_locals_logging():
    secret = "prod-token"
    try:
        raise RuntimeError("failed op")
    except Exception:
        print({"locals": locals(), "secret": secret})
        raise


# Vulnerable: LOG-013 (Missing security heartbeat)
async def log013_no_security_heartbeat():
    return None


# Vulnerable: LOG-014 (High-privilege action only in app log)
@app.post("/log014/admin/users/{uid}/disable")
async def log014_disable_user(uid: int):
    print(f"disabled user {uid}")
    return {"disabled": uid}

