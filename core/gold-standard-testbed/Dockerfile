FROM python:3.11

# Vulnerable: INF-4.1 (No dedicated non-root user)
# Vulnerable: INF-4.4 (Secrets in ENV/LABEL)
# Vulnerable: DOCK-010 (Runs as root)
# Vulnerable: DOCK-011 (No non-root USER in final stage)
# Vulnerable: DOCK-013 (latest tag usage)
# Vulnerable: DOCK-016 (Secret in ARG/ENV)
ENV DB_PASSWORD=supersecret
ARG API_TOKEN=prod-secret
LABEL api_token="prod-token-123"

# Intentionally insecure permissions to validate infra hardening detections.
# Vulnerable: DOCK-015 (Package cache not cleaned in same layer)
RUN chmod 777 /app

# Vulnerable: DOCK-014 (ADD remote URL)
ADD https://example.com/app.tar.gz /opt/

# Vulnerable: DOCK-017 (No HEALTHCHECK)
# Vulnerable: DOCK-018 (Privileged runtime expected)
# Vulnerable: DOCK-019 (docker.sock mount expected in runtime)
# Vulnerable: DOCK-020 (No seccomp profile at runtime)
# Vulnerable: DOCK-012 (Read-only rootfs not enforced)

