# Vulnerable: ITS-001
import jwt

payload = jwt.decode(token, options={"verify_signature": False})

# Vulnerable: ITS-002
vault_token = "s.abcdefghijklmnopqrstuvwxy12345"

# Vulnerable: RRC-013
KEYCLOAK_USER = "admin"
KEYCLOAK_PASSWORD = "admin123"

# Vulnerable: ITS-004
import requests
resp = requests.post(CLINKER_URL, json=payload)

# Vulnerable: ITS-005
data = requests.get("https://upstream.internal/api")

# Vulnerable: ITS-006
for _ in range(10):
    call_api()

# Vulnerable: ITS-007
# POST /payments/transfer
# no idempotency key
