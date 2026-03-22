# Gold testbed: Advanced Agent & Cloud (AAC) — Python-oriented markers.
# Vulnerable: AAC-001 (SSRF Playwright)
async def _aac001(page, userInput):
    await page.goto(userInput)


# Vulnerable: AAC-002 (Playwright trace / PII)
async def _aac002(context):
    await context.tracing.start(screenshots=True)


# Vulnerable: AAC-004 (pickle in RQ-style job)
import pickle


def _aac4(raw_job: bytes):
    return pickle.loads(raw_job)


# Vulnerable: AAC-005 (MinIO presigned PUT, weak TTL)
from datetime import timedelta

from minio import Minio  # type: ignore


def _aac5(client: Minio):
    return client.presigned_put_object("bucket", "obj", expires=timedelta(days=7))


# Vulnerable: AAC-006 (token presence without validation)
def _aac6(authorization: str | None, url: str):
    import requests

    if authorization:
        return requests.get(url, headers={"Authorization": authorization})
    return None


# Vulnerable: AAC-007 (nginx API without limit_req)
AAC7_NGINX = """
location /api/ {
    proxy_pass http://backend;
}
"""


# Vulnerable: AAC-008 (egress proxy bypass)
def _aac8(url: str):
    import requests

    return requests.get(url, proxies={"http": None, "https": None})


# Vulnerable: AAC-009 (log injection from Redis payload)
def _aac9(logger, redis_raw_payload: str):
    logger.info("job=%s", redis_raw_payload)
