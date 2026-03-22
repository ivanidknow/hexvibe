"""
Optional HTTP integration checks for observability / logging patterns (LOG-*).
Migrated from skills/observability/verify_poc.py.

Static Semgrep/marker ground truth: gold-standard-testbed/api_vulnerable.py (Vulnerable: LOG-*).
"""
from __future__ import annotations

import os
from uuid import uuid4

import httpx
import pytest

BASE_URL = os.getenv("HEXVIBE_TARGET_URL", "http://127.0.0.1:8000")


@pytest.mark.asyncio
async def test_trace_id_propagated_in_response_headers() -> None:
    trace_id = str(uuid4())
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as client:
        resp = await client.get("/health", headers={"X-Trace-ID": trace_id})
    assert resp.status_code == 200
    assert resp.headers.get("X-Trace-ID") in {trace_id, resp.headers.get("x-trace-id")}


@pytest.mark.asyncio
async def test_internal_error_is_sanitized() -> None:
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as client:
        resp = await client.get("/debug/raise")
    assert resp.status_code == 500
    body = resp.text.lower()
    assert "traceback" not in body
    assert "password" not in body
    assert "secret" not in body


@pytest.mark.asyncio
async def test_failed_login_emits_security_relevant_status() -> None:
    payload = {"username": "alice", "password": "wrong-password"}
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as client:
        resp = await client.post("/auth/login", json=payload)
    assert resp.status_code in {401, 429}


@pytest.mark.asyncio
async def test_log_injection_sanitized() -> None:
    injected = "alice\r\nX-Fake-Log: injected"
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as client:
        resp = await client.get("/search", params={"q": injected})
    assert resp.status_code in {200, 400, 422}
    assert "\r\n" not in resp.text


@pytest.mark.asyncio
async def test_trace_id_header_propagation() -> None:
    trace_id = str(uuid4())
    headers = {"X-Trace-ID": trace_id}
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as client:
        resp = await client.get("/proxy/upstream-health", headers=headers)
    assert resp.status_code in {200, 502}
    if resp.status_code == 200:
        echoed = resp.headers.get("X-Upstream-Trace-ID") or resp.json().get("upstream_trace_id")
        assert echoed == trace_id
