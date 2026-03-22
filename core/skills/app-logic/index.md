# Application Business Logic

## Stack overview

Cross-cutting **BOLA/BOPLA**, workflow, webhook, and abuse-resistant business rules on typical FastAPI-style services. Metrics are prefixed **`BIZ`**.

## Top threats

- Object and property-level authorization gaps (`BIZ-001`–`BIZ-004`, `BIZ-009`).
- Step-up auth and replay/idempotency (`BIZ-005`–`BIZ-008`, `BIZ-010`).
- SSRF and trust of internal services (`BIZ-011`, `BIZ-012`).
- Shadow APIs, exports, and webhooks (`BIZ-013`, `BIZ-016`–`BIZ-019`).

## Pattern catalog

Complete Anti-Pattern / Safe-Pattern definitions live in [`patterns.md`](patterns.md). The table below is a **table of contents** by metric ID.

| ID | Metric | Stack |
|---|---|---|
| `BIZ-001` | BOLA: доступ к объекту по `id` без ownership check | `@app.get("/orders/{order_id}")` `async def get_order(order_id: int, user=Depends(current_user)):` `    order = await repo.get_order(order_id)` `    if not order or order.owner_id != user.id:` `        raise HTTPException(status_code=404, detail="not found")` `    return order` |
| `BIZ-002` | BOLA: доверие `user_id` из query/body | `@app.get("/profile")` `async def profile(user=Depends(current_user)):` `    return await repo.get_profile(user.id)` |
| `BIZ-003` | BOPLA: массовое обновление защищенных полей | `OWASP API Security Top 10 (2023) API3: Broken Object Property Level Authorization` |
| `BIZ-004` | Vertical privilege escalation через `role` из клиентского payload | `@app.post("/admin/promote")` `async def promote(dto: PromoteUserDTO, actor=Depends(current_user)):` `    if actor.role != "admin":` `        raise HTTPException(status_code=403, detail="forbidden")` `    if dto.role not in {"manager", "auditor"}:` `        raise HTTPException(status_code=400, detail="invalid role")` `    await repo.update_user(dto.user_id, role=dto.role)` |
| `BIZ-005` | MFA bypass: высокорисковая операция без step-up статуса | `@app.post("/payments/{payment_id}/confirm")` `async def confirm(payment_id: int, user=Depends(current_user)):` `    if not user.step_up_verified_at or user.step_up_verified_at < datetime.now(timezone.utc) - timedelta(minutes=5):` `        raise HTTPException(status_code=401, detail="step-up required")` `    return await payments.confirm(payment_id, user.id)` |
| `BIZ-006` | Missing transaction binding: подтверждение операции не связано с challenge | `@app.post("/mfa/verify")` `async def verify(req: MFAVerifyRequest, user=Depends(current_user)):` `    challenge = await mfa.get_challenge(req.challenge_id)` `    if not challenge or challenge.user_id != user.id or challenge.context != req.context:` `        raise HTTPException(status_code=400, detail="invalid challenge")` `    if not await mfa.verify_code(user.id, req.code):` `        raise HTTPException(status_code=401, detail="invalid code")` `    await mfa.mark_step_up(user.id, context=req.context)` `    return {"ok": True}` |
| `BIZ-007` | Broken workflow: пропуск обязательного шага (draft->paid напрямую) | `ALLOWED = {"draft": {"submitted"}, "submitted": {"approved"}, "approved": {"paid"}}` `@app.post("/orders/{order_id}/pay")` `async def pay(order_id: int, user=Depends(current_user)):` `    order = await repo.get_order(order_id)` `    if not order or order.owner_id != user.id:` `        raise HTTPException(status_code=404, detail="not found")` `    if "paid" not in ALLOWED.get(order.status, set()):` `        raise HTTPException(status_code=409, detail="invalid transition")` `    await repo.update_order(order_id, status="paid")` |
| `BIZ-008` | Replay на критический endpoint без idempotency key | `@app.post("/transfers")` `async def transfer(req: TransferRequest, request: Request, user=Depends(current_user)):` `    idem = request.headers.get("Idempotency-Key", "").strip()` `    if not idem:` `        raise HTTPException(status_code=400, detail="missing idempotency key")` `    if await idem_store.exists(user.id, idem):` `        raise HTTPException(status_code=409, detail="duplicate request")` `    result = await svc.transfer(user.id, req.target_id, req.amount)` `    await idem_store.save(user.id, idem)` `    return result` |
| `BIZ-009` | Tenant breakout: отсутствие tenant-scope в выборке | `@app.get("/invoices/{invoice_id}")` `async def invoice(invoice_id: int, user=Depends(current_user)):` `    inv = await repo.get_invoice(invoice_id)` `    if not inv or inv.tenant_id != user.tenant_id:` `        raise HTTPException(status_code=404, detail="not found")` `    return inv` |
| `BIZ-010` | Sensitive action без re-auth при long-lived session | `@app.post("/users/me/change-email")` `async def change_email(req: ChangeEmailRequest, user=Depends(current_user)):` `    if not await auth.verify_password(user.id, req.current_password):` `        raise HTTPException(status_code=401, detail="re-auth required")` `    await repo.update_user(user.id, email=req.new_email)` |
| `BIZ-011` | Business SSRF: сетевой вызов с необработанным пользовательским URL | `def _is_blocked_host(host: str) -> bool:` `    if host in {"localhost"}:` `        return True` `    try:` `        ip = ipaddress.ip_address(host)` `        return ip.is_private or ip.is_loopback or ip.is_link_local` `    except ValueError:` `        return False` `@app.post("/preview")` `async def preview(dto: PreviewRequest):` `    parsed = urlparse(dto.url)` `    if parsed.scheme not in {"https"} or not parsed.hostname or _is_blocked_host(parsed.hostname):` `        raise HTTPException(status_code=400, detail="blocked target")` `    async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:` `        r = await client.get(dto.url)` `    return {"status": r.status_code}` |
| `BIZ-012` | Insecure Internal Trust: слепое доверие данным внутреннего сервиса | `class RiskResponse(BaseModel):` `    user_id: int` `    risk_level: Literal["low", "medium", "high"]` `    allow_transfer: bool` `@app.get("/risk/{user_id}")` `async def risk(user_id: int):` `    async with httpx.AsyncClient(timeout=5.0) as client:` `        r = await client.get(f"http://risk.internal/score/{user_id}")` `    r.raise_for_status()` `    data = RiskResponse.model_validate(r.json())` `    if data.user_id != user_id:` `        raise HTTPException(status_code=502, detail="upstream mismatch")` `    return {"allow_transfer": data.allow_transfer}` |
| `BIZ-013` | Shadow API Exposure: debug/legacy endpoint активен в prod | `def create_app(env: str) -> FastAPI:` `    app = FastAPI()` `    if env != "prod":` `        @app.get("/debug/sql")` `        async def debug_sql():` `            return {"ok": True}` `    return app` `@app.get("/legacy/report", include_in_schema=False)` `async def legacy_report():` `    raise HTTPException(status_code=410, detail="endpoint removed")` |
| `BIZ-014` | Non-Atomic Financial Operations: неатомарное обновление баланса | `@app.post("/wallet/transfer")` `async def transfer(req: TransferRequest, db=Depends(get_db)):` `    async with db.transaction():` `        src = await repo.get_wallet_for_update(req.src_id, db)` `        dst = await repo.get_wallet_for_update(req.dst_id, db)` `        if src.balance < req.amount:` `            raise HTTPException(status_code=409, detail="insufficient funds")` `        await repo.update_balance(req.src_id, -req.amount, db)` `        await repo.update_balance(req.dst_id, req.amount, db)` |
| `BIZ-015` | Parameter Pollution (HPP): дубли query-параметров влияют на логику | `@app.get("/search")` `async def search(request: Request):` `    roles = request.query_params.getlist("role")` `    if len(roles) != 1:` `        raise HTTPException(status_code=400, detail="duplicate role parameter")` `    role = roles[0]` `    if role not in {"user", "manager"}:` `        raise HTTPException(status_code=400, detail="invalid role")` `    return await repo.search(role=role)` |
| `BIZ-016` | Unrestricted Export Size: экспорт без лимита количества записей | `MAX_EXPORT_ROWS = 10000` `@app.get("/exports/orders.csv")` `async def export_orders(limit: int = 1000):` `    if limit <= 0 or limit > MAX_EXPORT_ROWS:` `        raise HTTPException(status_code=400, detail="limit out of range")` `    rows = await repo.list_orders(limit=limit)` `    return to_csv(rows)` |
| `BIZ-017` | CSV/Excel Formula Injection: спецсимволы не нейтрализуются при экспорте | `DANGEROUS_PREFIXES = ("=", "+", "-", "@")` `def sanitize_cell(value: str) -> str:` `    if value.startswith(DANGEROUS_PREFIXES):` `        return "'" + value` `    return value` `def row_to_csv(user: dict[str, str]) -> list[str]:` `    return [` `        sanitize_cell(user["name"]),` `        sanitize_cell(user["email"]),` `        sanitize_cell(user["comment"]),` `    ]` |
| `BIZ-018` | Trusting Client-Side Calculations: сервер принимает цену/скидку от клиента | `@app.post("/checkout")` `async def checkout(req: CheckoutRequest, user=Depends(current_user)):` `    items = await catalog.get_items(req.item_ids)` `    subtotal = sum(item.price for item in items)` `    discount = await promotions.calculate_discount(user.id, req.promo_code, items)` `    total = max(subtotal - discount, 0)` `    if req.client_total is not None and abs(req.client_total - total) > Decimal("0.01"):` `        raise HTTPException(status_code=400, detail="price tampering detected")` `    await billing.charge(user.id, total)` |
| `BIZ-019` | Webhook Signature Verification Missing: внешние callback-и принимаются без подписи | `@app.post("/webhook/payment")` `async def payment_webhook(request: Request):` `    body = await request.body()` `    sig = request.headers.get("x-signature", "")` `    if not verify_hmac(body, sig, webhook_secret):` `        raise HTTPException(status_code=401, detail="invalid signature")` `    payload = json.loads(body)` `    ...` `    await payments.mark_paid(payload["order_id"])` |
| `BIZ-020` | RQ worker/queue without explicit safe serializer policy | Явно задавать безопасный serializer (json/msgpack), запретить pickle в job payload и валидировать схему аргументов задач. |
| `BIZ-021` | httpx call without explicit timeout (resource exhaustion risk) | Всегда задавать `timeout` (и retry budget), чтобы исключить зависание и неконтролируемое потребление ресурсов. |

## Verification

**Verification:** Check the gold testbed file(s) below for `Vulnerable: <ID>` markers (static Semgrep + `detection-matrix.md` ground truth).

- [`gold-standard-testbed/api_vulnerable.py`](../gold-standard-testbed/api_vulnerable.py)

**Optional HTTP integration tests** (pytest + httpx; require a running API, `HEXVIBE_TARGET_URL`): [`gold-standard-testbed/integration/verify_app_logic_poc.py`](../gold-standard-testbed/integration/verify_app_logic_poc.py). See [`gold-standard-testbed/integration/README.md`](../gold-standard-testbed/integration/README.md).

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

