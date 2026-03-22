# Vulnerable: PY-001
from fastapi import FastAPI
app = FastAPI(debug=True)

# Vulnerable: PY-002
try:
    run()
except Exception as e:
    out = {"error": str(e)}

# Vulnerable: PY-003
import pickle
obj = pickle.loads(payload)

# Vulnerable: PY-004
import subprocess
subprocess.run(cmd, shell=True)

# Vulnerable: PY-005
import yaml
cfg = yaml.load(data, Loader=yaml.Loader)

# Vulnerable: PY-006
import tempfile
name = tempfile.mktemp()

# Vulnerable: PY-007
import requests
requests.get(user_url)

# Vulnerable: PY-008
requests.get("https://api.internal")

# Vulnerable: PY-009
SECRET_KEY = "dev-secret"

# Vulnerable: PY-010
import random
token = str(random.random())

# Vulnerable: PY-011
import jwt
jwt.decode(token, key, options={"verify_signature": True})

# Vulnerable: PY-012
session.execute(f"SELECT * FROM users WHERE id={uid}")

# Vulnerable: PY-013
user = User(**request_json)

# Vulnerable: PY-014
open(base + "/" + filename, "r")

# Vulnerable: PY-015
eval(user_expr)

# Vulnerable: PY-016
cors_cfg = {"allow_origins": ["*"], "allow_credentials": True}

# Vulnerable: PY-017
@app.post("/login")
def login():
    return {"ok": True}

# Vulnerable: PY-018
async def endpoint():
    requests.get("https://x")

# Vulnerable: PY-019
browser = p.chromium.launch(args=["--no-sandbox"])

# Vulnerable: PY-020
@app.get("/users/{id}")
def get_user(id: int):
    return db_user

# Vulnerable: PY-021
from sqlalchemy import text
q = text(f"SELECT * FROM users WHERE name='{name}'")

# Vulnerable: PY-022
model = UserModel.model_construct(**payload)

# Vulnerable: PY-023
page = shared_browser.new_page()

# Vulnerable: PY-024
import httpx
client = httpx.Client(verify=False)

# Vulnerable: PY-025
def webhook(req):
    return req.body

# Vulnerable: PY-026
logger.info("token=%s", token)

# Vulnerable: PY-027
limit = int(req.args["limit"])

# Vulnerable: PY-028
def transfer():
    return "done"

# Vulnerable: PY-029
celery_serializer = "pickle"

# Vulnerable: PY-030
from fastapi.responses import RedirectResponse
resp = RedirectResponse(next_url)
