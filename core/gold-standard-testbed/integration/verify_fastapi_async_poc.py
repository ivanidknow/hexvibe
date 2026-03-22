"""
Optional HTTP integration checks for FastAPI/async patterns (FAS-*).
Migrated from skills/fastapi-async/verify_poc.py.

Static Semgrep/marker ground truth: gold-standard-testbed/api_vulnerable.py (Vulnerable: FAS-*).
"""
from __future__ import annotations

import asyncio
import os
import time

import httpx
import pytest

BASE_URL = os.getenv("HEXVIBE_TARGET_URL", "http://127.0.0.1:8000")


@pytest.mark.asyncio
async def test_async_endpoint_latency_budget() -> None:
    started = time.monotonic()
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as client:
        resp = await client.get("/health")
    elapsed = time.monotonic() - started
    assert resp.status_code == 200
    assert elapsed < 1.0


@pytest.mark.asyncio
async def test_sql_injection_payload_rejected() -> None:
    payload = {"username": "admin' OR 1=1 --"}
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as client:
        resp = await client.post("/users/search", json=payload)
    assert resp.status_code in {400, 422}


@pytest.mark.asyncio
async def test_concurrent_requests() -> None:
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as client:

        async def one_call() -> int:
            resp = await client.get("/health")
            return resp.status_code

        codes = await asyncio.gather(*(one_call() for _ in range(25)))

    assert all(code == 200 for code in codes)
