# Gold testbed: Cloud & Secrets (SEC) — Python-oriented markers.

# Vulnerable: SEC-001 (SSRF to metadata API)
# requests.get("http://169.254.169.254/latest/meta-data/")

# Vulnerable: SEC-006 (ENV leakage to logs)
# logger.info("env=%s", os.environ)

# Vulnerable: SEC-007 (Hardcoded cloud credentials)
# AWS_SECRET_ACCESS_KEY = "AKIA..."

# Vulnerable: SEC-008 (Insecure JWT validation)
# jwt.decode(token, options={"verify_signature": False})

# Vulnerable: SEC-009 (Vault token in plain config)
# vault_token: s.xxxxx

# Vulnerable: SEC-010 (Vault TLS verification disabled)
# vault_client = hvac.Client(url=VAULT_URL, verify=False)

# Vulnerable: SEC-011 (Unencrypted secret in object storage)
# s3.put_object(Bucket=b, Key=k, Body=secret_blob)

# Vulnerable: SEC-013 (Publicly exposed secrets endpoint)
# @app.get("/debug/secrets")
# def dump(): return os.environ

# Vulnerable: SEC-014 (Missing secret rotation policy)
# rotation_days = None

# Vulnerable: SEC-015 (Unsafe secret in CI variables)
# echo $PROD_DB_PASSWORD

