# Observability & Audit Logging

## Stack overview

Structured logging, trace correlation, audit integrity, and security telemetry for Python services. Metrics are prefixed **`LOG`**.

## Top threats

- Silent failures and missing correlation (`LOG-001`–`LOG-003`, `LOG-010`).
- PII/secrets in logs and verbose errors (`LOG-004`, `LOG-005`, `LOG-012`).
- Missing audit for admin and auth events (`LOG-006`, `LOG-007`, `LOG-014`).
- Log injection (`LOG-011`).

## Pattern catalog

Complete Anti-Pattern / Safe-Pattern definitions live in [`patterns.md`](patterns.md). The table below is a **table of contents** by metric ID.

| ID | Metric | Stack |
|---|---|---|
| `LOG-001` | Silent Exception: `except Exception: pass` | `try:` `    await repo.save(event)` `except Exception:` `    logger.exception("audit-save-failed", extra={"event_type": event.type})` `    raise` |
| `LOG-002` | Missing Trace-ID в логах запроса | `trace_id = request.headers.get("x-trace-id") or str(uuid4())` `logger.info("request accepted", extra={"trace_id": trace_id, "path": request.url.path})` `response.headers["X-Trace-ID"] = trace_id` |
| `LOG-003` | Unstructured logs: текст без контекста безопасности | `logger.warning("auth_failed", extra={"trace_id": trace_id, "user": username, "ip": client_ip, "reason": "bad_credentials"})` |
| `LOG-004` | PII/secret leakage in logs | `safe = {"username": payload.get("username"), "mfa": payload.get("mfa")}` `logger.info("auth payload sanitized", extra={"trace_id": trace_id, "payload": safe})` |
| `LOG-005` | Verbose stack traces returned to API client | `except Exception:` `    logger.exception("unhandled error", extra={"trace_id": trace_id})` `    raise HTTPException(status_code=500, detail="internal server error")` |
| `LOG-006` | Missing audit events for role/permission changes | `@app.post("/admin/users/{uid}/role")` `async def set_role(uid: int, role: str, actor=Depends(current_user)):` `    await repo.set_role(uid, role)` `    await audit_log.write({"event": "role_change", "actor_id": actor.id, "target_user_id": uid, "new_role": role, "trace_id": trace_id})` |
| `LOG-007` | Missing failed-auth telemetry and lockout signals | `if not auth_ok:` `    await audit_log.write({"event": "auth_failed", "username": username, "ip": client_ip, "trace_id": trace_id})` `    await risk_counter.bump(f"auth:{username}:{client_ip}")` `    raise HTTPException(status_code=401, detail="invalid credentials")` |
| `LOG-008` | No request/response latency telemetry | `@app.middleware("http")` `async def m(request: Request, call_next):` `    started = time.perf_counter()` `    response = await call_next(request)` `    elapsed_ms = (time.perf_counter() - started) * 1000` `    logger.info("http_access", extra={"trace_id": request.state.trace_id, "path": request.url.path, "status": response.status_code, "latency_ms": round(elapsed_ms, 2)})` `    return response` |
| `LOG-009` | Logs without integrity controls/immutability for security events | `record = {"event": "payment_approved", "id": pid, "trace_id": trace_id, "ts": datetime.now(timezone.utc).isoformat()}` `record["sig"] = hmac_sha256(audit_signing_key, json.dumps(record, sort_keys=True))` `await append_only_audit_store.write(record)` |
| `LOG-010` | No centralized exception handler for sanitization and correlation | `@app.exception_handler(Exception)` `async def handle_exc(request: Request, exc: Exception):` `    trace_id = getattr(request.state, "trace_id", "n/a")` `    logger.exception("unhandled", extra={"trace_id": trace_id, "path": request.url.path})` `    return JSONResponse(status_code=500, content={"detail": "internal server error", "trace_id": trace_id})` |
| `LOG-011` | Log Injection Protection: CR/LF из пользовательских данных попадают в лог | `def sanitize_for_log(value: str) -> str:` `    return value.replace("\\r", "\\\\r").replace("\\n", "\\\\n")` `@app.get("/search")` `async def search(q: str):` `    safe_q = sanitize_for_log(q)` `    logger.info("search query=%s", safe_q)` `    return {"ok": True}` |
| `LOG-012` | Sensitive Data in Exception Context: логирование `locals()` в prod | `except Exception:` `    logger.exception("failed", extra={"trace_id": trace_id, "context": {"operation": "payment_create"}})` `    raise` `# production logger must not capture locals or full frame dumps` |
| `LOG-013` | Missing Security Heartbeat: нет периодических контрольных событий мониторинга | `async def security_heartbeat_task() -> None:` `    while True:` `        await audit_log.write({"event": "security_heartbeat", "service": "api", "status": "ok", "ts": datetime.now(timezone.utc).isoformat()})` `        await asyncio.sleep(60)` `@app.on_event("startup")` `async def start_heartbeat() -> None:` `    asyncio.create_task(security_heartbeat_task())` |
| `LOG-014` | High-Privilege Action Audit: админ-действия пишутся в обычный app log | `@app.post("/admin/users/{uid}/disable")` `async def disable_user(uid: int, actor=Depends(current_user)):` `    logger.info("admin action requested", extra={"trace_id": trace_id, "actor_id": actor.id})` `    await security_audit_log.write({"event": "admin_user_disable", "actor_id": actor.id, "target_user_id": uid, "trace_id": trace_id, "ts": datetime.now(timezone.utc).isoformat()})` |
| `LOG-015` | Системный лог: пароль в plaintext (`syslog`/journald) (CWE-312) | Structured logging + redaction filter для password fields. |
| `LOG-016` | Docker/k8s: `env` секреты в stdout контейнера (CWE-532) | Log scrubber sidecar; deny `print(environ)` in prod. |
| `LOG-017` | Windows Event Log: токен в `EventLog.WriteEntry` (CWE-312) | Token hash or presence flag only in EventLog. |
| `LOG-018` | `journalctl`/structured log с Bearer в поле message (CWE-532) | Redact `Authorization`/`Cookie` keys globally. |
| `LOG-019` | OpenTelemetry span: пароль в attributes (CWE-532) | OTel semantic conventions + scrubbing processor. |
| `LOG-020` | Избыточное логирование полного HTTP-тела ответа с PII (CWE-779) | Sampling + redaction; max body length 0 in prod logs. |

## Verification

**Verification:** Check the gold testbed file(s) below for `Vulnerable: <ID>` markers (static Semgrep + `detection-matrix.md` ground truth).

- [`gold-standard-testbed/api_vulnerable.py`](../gold-standard-testbed/api_vulnerable.py)

**Optional HTTP integration tests** (pytest + httpx; require a running API, `HEXVIBE_TARGET_URL`): [`gold-standard-testbed/integration/verify_observability_poc.py`](../gold-standard-testbed/integration/verify_observability_poc.py). See [`gold-standard-testbed/integration/README.md`](../gold-standard-testbed/integration/README.md).

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

