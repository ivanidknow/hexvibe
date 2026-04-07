# Java Enterprise Security

## Stack overview

Enterprise Java security patterns for `Java 21+`, `Spring Boot 3.3+`, `Camunda 7.20`, `PostgreSQL`, `Elasticsearch`, and deployment hardening (`Docker`, `Kubernetes`, `Nginx`).

## Pattern families

- `CAM-*`: Camunda process/auth/transaction threats.
- `SPR-*`: Spring API, auth, deserialization, and error-handling threats.
- `AK-*`: Keycloak/JWT/OAuth2 integration flaws.
- `DB-*`: Database injection/access-control/resource risks.
- `ES-*`: Elasticsearch query/auth/concurrency risks.
- `INF-*`: Container and platform hardening anti-patterns.

## Pattern catalog

Canonical detections and remediations are maintained in [`patterns.md`](patterns.md).

## Verification

Use the gold testbed markers `// Vulnerable: <ID>` in:

- [`core/gold-standard-testbed/enterprise_java_validation.java`](../../gold-standard-testbed/enterprise_java_validation.java)

After updates, regenerate rules and matrix:

```bash
python scripts/sync_semgrep.py
python scripts/generate_detection_matrix.py
```
