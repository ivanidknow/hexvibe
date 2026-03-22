"""
Optional HTTP integration checks complementing infra patterns (INF-*).
Migrated from skills/infra-k8s-helm/verify_poc.py.

Static Semgrep/marker ground truth: gold-standard-testbed/Dockerfile, nginx.conf,
infra_vulnerable.yaml (Vulnerable: INF-*).
"""
from __future__ import annotations

import os

import httpx
import pytest

BASE_URL = os.getenv("HEXVIBE_TARGET_URL", "http://127.0.0.1:8000")


@pytest.mark.asyncio
async def test_sensitive_ports_not_exposed_via_probe() -> None:
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.get(f"{BASE_URL}/meta/public-ports")
    assert resp.status_code == 200
    ports = resp.json().get("ports", [])
    assert 5432 not in ports
    assert 6379 not in ports


@pytest.mark.asyncio
async def test_runtime_not_privileged_flag() -> None:
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as client:
        resp = await client.get("/meta/runtime-security")
    assert resp.status_code == 200
    assert resp.json().get("privileged") is False
