"""
Optional HTTP integration checks for application business-logic patterns (BIZ-*).
Migrated from skills/app-logic/verify_poc.py.

Static Semgrep/marker ground truth: gold-standard-testbed/api_vulnerable.py (Vulnerable: BIZ-*).
"""
from __future__ import annotations

import asyncio
import os

import httpx
import pytest

BASE_URL = os.getenv("HEXVIBE_TARGET_URL", "http://127.0.0.1:8000")


@pytest.mark.asyncio
async def test_bola_order_id_swap_forbidden() -> None:
    headers_user_a = {"Authorization": "Bearer user-a-token"}
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as client:
        resp = await client.get("/orders/2002", headers=headers_user_a)
    assert resp.status_code in {403, 404}


@pytest.mark.asyncio
async def test_mass_assignment_is_admin_rejected() -> None:
    payload = {"email": "user@example.com", "is_admin": True, "balance": 999999}
    headers = {"Authorization": "Bearer user-token"}
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as client:
        resp = await client.patch("/accounts/1001", json=payload, headers=headers)
    assert resp.status_code in {400, 403, 422}


@pytest.mark.asyncio
async def test_sensitive_flow_requires_step_up() -> None:
    headers = {"Authorization": "Bearer session-without-stepup"}
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as client:
        resp = await client.post("/payments/501/confirm", headers=headers)
    assert resp.status_code in {401, 403}


@pytest.mark.asyncio
async def test_transfer_requires_idempotency_key() -> None:
    headers = {"Authorization": "Bearer user-token"}
    payload = {"target_id": 2002, "amount": 10}
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as client:
        resp = await client.post("/transfers", json=payload, headers=headers)
    assert resp.status_code in {400, 409}


@pytest.mark.asyncio
async def test_business_ssrf_blocked() -> None:
    headers = {"Authorization": "Bearer user-token"}
    payload = {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as client:
        resp = await client.post("/preview", json=payload, headers=headers)
    assert resp.status_code in {400, 403, 422}


@pytest.mark.asyncio
async def test_non_atomic_transfer_race_condition_guard() -> None:
    headers = {"Authorization": "Bearer user-token", "Idempotency-Key": "race-check"}
    payload = {"src_id": 1001, "dst_id": 2002, "amount": 5}

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as client:

        async def one_transfer() -> int:
            r = await client.post("/wallet/transfer", json=payload, headers=headers)
            return r.status_code

        statuses = await asyncio.gather(*(one_transfer() for _ in range(10)))

    assert any(code in {409, 429} for code in statuses) or len(set(statuses)) == 1


@pytest.mark.asyncio
async def test_export_limit_enforced() -> None:
    headers = {"Authorization": "Bearer user-token"}
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as client:
        resp = await client.get("/exports/orders.csv?limit=999999", headers=headers)
    assert resp.status_code in {200, 400}
    if resp.status_code == 200:
        content_range = resp.headers.get("Content-Range", "")
        assert "999999" not in content_range


@pytest.mark.asyncio
async def test_price_tampering_ignored() -> None:
    headers = {"Authorization": "Bearer user-token"}
    payload = {
        "item_ids": [101],
        "promo_code": None,
        "client_total": "0.01",
    }
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as client:
        resp = await client.post("/checkout", json=payload, headers=headers)
    assert resp.status_code in {400, 403, 409, 422}
