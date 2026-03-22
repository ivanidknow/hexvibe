"""
Optional HTTP integration checks for Auth / Keycloak patterns (AK-*).
Migrated from skills/auth-keycloak/verify_poc.py.

Static Semgrep/marker ground truth: gold-standard-testbed/api_vulnerable.py (Vulnerable: AK-*).
"""
from __future__ import annotations

import os

import httpx
import pytest

BASE_URL = os.getenv("HEXVIBE_TARGET_URL", "http://127.0.0.1:8000")


@pytest.mark.asyncio
async def test_rejects_invalid_issuer_token() -> None:
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as client:
        forged_token = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJldmlsLWlzc3VlciJ9."
        resp = await client.get(
            "/secure/profile",
            headers={"Authorization": f"Bearer {forged_token}"},
        )
    assert resp.status_code in {401, 403}


@pytest.mark.asyncio
async def test_rejects_wrong_audience_token() -> None:
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as client:
        wrong_aud_token = "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJvdGhlci1jbGllbnQifQ.sig"
        resp = await client.get(
            "/secure/profile",
            headers={"Authorization": f"Bearer {wrong_aud_token}"},
        )
    assert resp.status_code in {401, 403}
