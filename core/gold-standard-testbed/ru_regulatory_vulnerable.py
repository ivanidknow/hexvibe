# Gold testbed: RU Regulatory (RRC) — 152-FZ / КИИ / residency markers.

# Vulnerable: RRC-001 (PII logged to stdout / external logs)
# print(f"user={user.email}")
# logger.info("pii", extra={"fio": fio, "snils": snils, "email": email})

# Vulnerable: RRC-002 (PII sent to foreign APIs without anonymization)
# requests.post("https://api.openai.com", json={"text": pii})

# Vulnerable: RRC-003 (GOST: unsafe / non-certified crypto libraries)
# from cryptography.hazmat.primitives.ciphers import Cipher
# import Crypto.Cipher

# Vulnerable: RRC-004 (Import Substitution: hardcoded cloud metadata)
# http://169.254.169.254/latest/meta-data/

# Vulnerable: RRC-005 (Foreign DNS/NTP)
# nameserver 8.8.8.8
# server pool.ntp.org iburst

# Vulnerable: RRC-006 (Insecure External Repositories in CI/CD)
# pip install -i https://pypi.org/simple -r requirements.txt
# npm config set registry https://registry.npmjs.org/

# Vulnerable: RRC-007 (Information leakage in errors)
# return {"error": str(e), "stack": traceback.format_exc()}

# Vulnerable: RRC-008 (Missing security audit events)
# except AuthError:
#     return {"ok": False}

# Vulnerable: RRC-009 (Unsigned binary execution)
# subprocess.run(["/opt/bin/tool"])

# Vulnerable: RRC-010 (Insecure data deletion without wipe)
# os.remove(pii_file)

# Vulnerable: RRC-011 (Banned functions / insecure shell)
# os.system(user_cmd)
# subprocess.Popen(user_cmd, shell=True)

# Vulnerable: RRC-012 (Missing config integrity check)
# settings = json.load(open("config.json"))

# Vulnerable: RRC-013 (ГОСТ/ЦБ: "мясные" учетки вместо токенов УДИ/УДА)
# KEYCLOAK_USER=admin
# KEYCLOAK_PASSWORD=admin123

# Vulnerable: RRC-014 (ЦБ: нет ротации и короткого TTL токенов)
# token = "hardcoded-long-lived"
# expires_in = 99999999

# Vulnerable: RRC-015 (FAPI: implicit flow + no PKCE/mTLS)
# response_type=token
# grant_type=implicit
# curl https://idp/token

# Vulnerable: RRC-016 (Docker root user)
# FROM python:3.11
# USER root

# Vulnerable: RRC-017 (Vault/ESO violation with plain Secret)
# kind: Secret
# stringData:
#   password: plain-text

# Vulnerable: RRC-018 (Drop tech stack)
# FROM python:3.9
# php:7.4-fpm

# Vulnerable: RRC-019 (No Keycloak auth middleware)
# @app.get("/internal/payments")
# def handler():
#     return {"ok": True}

# Vulnerable: RRC-020 (Integrity checks missing before startup)
# app = load_binary("/opt/bin/service")
# config = open("/etc/service/config.yaml").read()

# Vulnerable: RRC-021 (No AV/IDS health checks in protected contour)
# start_service()
# # no AV/IDS/EDR readiness verification

# Vulnerable: RRC-022 (Static analysis results not persisted in CI logs)
# ci_stage("build")
# run_semgrep()
# # result not persisted

# Vulnerable: RRC-023 (Missing key rotation period in Vault/KMS policies)
# key_policy = {"name": "payments-key"}
# # no rotation_period

# Vulnerable: RRC-024 (No CSP/SRI and no UI integrity checks)
# <script src="https://cdn.example.com/widget.js"></script>
# # no Content-Security-Policy

# Vulnerable: RRC-025 (Payment details can change between create/sign)
# payment.amount = req.amount
# sign(payment)
# # payload changed before signing

# Vulnerable: RRC-026 (No post-quantum crypto migration strategy)
# crypto_profile = "rsa2048-only"

