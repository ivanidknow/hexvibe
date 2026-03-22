from fastapi import FastAPI
from sqlalchemy import text

app = FastAPI(title="HexVibe Gold Standard Testbed")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/users/search")
async def users_search(username: str) -> dict[str, str]:
    # Intentionally vulnerable query for scanner calibration.
    _query = text(f"SELECT * FROM users WHERE username = '{username}'")
    return {"note": "Intentionally vulnerable endpoint for security calibration."}


@app.get("/secure/profile")
async def secure_profile() -> dict[str, str]:
    # Intentionally simplified: real app should validate JWT signature, iss and aud.
    return {"profile": "demo"}
