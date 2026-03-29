# Infra / Kubernetes / Helm / Docker

## Stack overview

**Kubernetes** manifests, **Helm** values, **Docker** images, and **NGINX** hardening. Metrics use the **`INF-*`** namespace (including dotted IDs).

## Top threats

- Privileged containers, weak TLS, and bad defaults in images (`INF-4.*`, `INF-5.*`, `INF-010`–`INF-014`).
- NGINX and ingress misconfiguration (`INF-5.3.*`, `INF-5.5.*`, `INF-5.6.*`).

## Pattern catalog

Complete Anti-Pattern / Safe-Pattern definitions live in [`patterns.md`](patterns.md). The table below is a **table of contents** by metric ID.

| ID | Metric | Stack |
|---|---|---|
| `INF-4.1` | Dockerfile без выделенного непривилегированного пользователя | `FROM python:3.11` `WORKDIR /app` `RUN groupadd -r app && useradd -r -g app app` `COPY . /app` `RUN chown -R app:app /app` `USER app` `CMD ["python","main.py"]` |
| `INF-5.10` | Нет ограничений памяти и CPU для контейнера | `services:` `  api:` `    image: example/api:1.0.0` `    mem_limit: "512m"` `    cpu_shares: 512` |
| `INF-5.2.1` | Привилегированный контейнер используется | `apiVersion: v1` `kind: Pod` `metadata:` `  name: restricted-pod` `spec:` `  containers:` `  - name: app` `    image: nginx:1.27` `    securityContext:` `      privileged: false` |
| `INF-5.2.4` | `allowPrivilegeEscalation` не запрещен | `apiVersion: apps/v1` `kind: Deployment` `metadata:` `  name: ape-off` `spec:` `  template:` `    spec:` `      containers:` `      - name: app` `        image: example/app:1.0.0` `        securityContext:` `          allowPrivilegeEscalation: false` |
| `INF-5.2.5` | Контейнер запускается с root GID | `apiVersion: v1` `kind: Pod` `metadata:` `  name: non-root-gid` `spec:` `  containers:` `  - name: app` `    image: example/app:1.0.0` `    securityContext:` `      runAsNonRoot: true` `      runAsGroup: 10001` |
| `INF-5.3.1` | NetworkPolicies не определены | `apiVersion: networking.k8s.io/v1` `kind: NetworkPolicy` `metadata:` `  name: app-default-deny` `  namespace: default` `spec:` `  podSelector:` `    matchLabels:` `      app: app` `  policyTypes:` `  - Ingress` `  - Egress` `  ingress: []` `  egress: []` |
| `INF-2.5.1` | NGINX раскрывает версию (`server_tokens on`) | `server {` `  listen 80;` `  server_tokens off; # CIS: скрыть версию NGINX` `}` |
| `INF-5.3.2` | NGINX без Content-Security-Policy | `server {` `  listen 443 ssl;` `  add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'self'; object-src 'none'" always; # CIS: CSP обязателен` `  location / { proxy_pass http://app; }` `}` |
| `INF-5.3.1-NGX` | NGINX без X-Frame-Options | `server {` `  listen 443 ssl;` `  add_header X-Frame-Options "DENY" always; # CIS: разрешено DENY или SAMEORIGIN` `  location / { proxy_pass http://app; }` `}` |
| `INF-1.2.1` | API Server допускает anonymous auth | `apiVersion: v1` `kind: Pod` `metadata:` `  name: kube-apiserver` `spec:` `  containers:` `  - name: kube-apiserver` `    command:` `    - kube-apiserver` `    - --anonymous-auth=false # CIS: запрет неаутентифицированного доступа` |
| `INF-1.2.6` | API Server без admission-control config файла | `apiVersion: v1` `kind: Pod` `metadata:` `  name: kube-apiserver` `spec:` `  containers:` `  - name: kube-apiserver` `    command:` `    - kube-apiserver` `    - --admission-control-config-file=/etc/kubernetes/admission-control.yaml # CIS: явно задать политику admission` |
| `INF-5.1.1` | Избыточное использование `cluster-admin` | `apiVersion: rbac.authorization.k8s.io/v1` `kind: Role` `metadata:` `  name: app-read-only` `  namespace: app` `rules:` `- apiGroups: [""]` `  resources: ["pods","services"]` `  verbs: ["get","list","watch"] # CIS: минимум привилегий` `---` `apiVersion: rbac.authorization.k8s.io/v1` `kind: RoleBinding` `metadata:` `  name: app-read-only-binding` `  namespace: app` `subjects:` `- kind: ServiceAccount` `  name: app-sa` `  namespace: app` `roleRef:` `  kind: Role` `  name: app-read-only` `  apiGroup: rbac.authorization.k8s.io` |
| `INF-5.6.2` | Pod без seccomp профиля | `apiVersion: v1` `kind: Pod` `metadata:` `  name: with-seccomp` `spec:` `  containers:` `  - name: app` `    image: nginx:1.27` `    securityContext:` `      seccompProfile:` `        type: RuntimeDefault # CIS: docker/default или runtime/default` |
| `INF-1.2.33` | Шифрование секретов в etcd не включено | `apiVersion: v1` `kind: Pod` `metadata:` `  name: kube-apiserver` `spec:` `  containers:` `  - name: kube-apiserver` `    command:` `    - kube-apiserver` `    - --encryption-provider-config=/etc/kubernetes/encryption-provider.yaml # CIS: encryption at rest for secrets` |
| `INF-4.4` | Dockerfile содержит секреты в `ENV`/`LABEL` | `FROM python:3.11` `ENV DB_PASSWORD_FILE=/run/secrets/db_password` `LABEL security.secrets=\"external-secret-store\" # no plaintext secrets` |
| `INF-5.25` | Монтирование `/var/run/docker.sock` в контейнер | `apiVersion: v1` `kind: Pod` `metadata:` `  name: no-docker-sock` `spec:` `  containers:` `  - name: app` `    image: alpine:3.20` `    volumeMounts:` `    - name: app-tmp` `      mountPath: /tmp` `  volumes:` `  - name: app-tmp` `    emptyDir: {}` |
| `INF-5.1.2-TLS` | Разрешены TLS 1.0/1.1 в NGINX | `server {` `  listen 443 ssl;` `  ssl_protocols TLSv1.2 TLSv1.3; # CIS: disable legacy TLS` `}` |
| `INF-5.5.1` | Не ограничены HTTP-методы | `location /api/ {` `  limit_except GET POST HEAD {` `    deny all; # CIS: allow only approved methods` `  }` `  proxy_pass http://backend;` `}` |
| `INF-010` | Hardcoded Credentials: захардкоженные пароли и токены в коде/манифестах | `services:` `  db:` `    image: postgres:16` `    environment:` `      POSTGRES_PASSWORD_FILE: /run/secrets/postgres_password` `      API_TOKEN_FILE: /run/secrets/api_token` `secrets:` `  postgres_password:` `    file: ./secrets/postgres_password` `  api_token:` `    file: ./secrets/api_token` |
| `INF-011` | Committed Private Keys: приватные ключи в репозитории | `tls.crt` `tls.key` `# secrets are provisioned at deploy time via external secret manager` `apiVersion: external-secrets.io/v1beta1` `kind: ExternalSecret` `metadata:` `  name: app-tls` `spec:` `  secretStoreRef:` `    name: vault-store` `    kind: ClusterSecretStore` `  target:` `    name: app-tls` `  data:` `  - secretKey: tls.key` `    remoteRef:` `      key: kv/prod/app/tls_key` |
| `INF-012` | Insecure .gitignore: секретные конфиги не исключены из Git | `# .gitignore` `.env` `.env.*` `secrets/` `*.pem` `*.key` `*credentials*.json` `!.env.example` |
| `INF-013` | Mutable Image Tags: использование `:latest` без digest pinning | `apiVersion: apps/v1` `kind: Deployment` `spec:` `  template:` `    spec:` `      containers:` `      - name: api` `        ...` `        image: org/api@sha256:3b5f...` |
| `INF-014` | Auto-mounted ServiceAccount Token: токен пода доступен без необходимости | `apiVersion: v1` `kind: Pod` `metadata:` `  name: app-pod` `spec:` `  automountServiceAccountToken: false` `  ...` `  containers:` `  - name: app` `    image: org/app:1.0.0` |
| `K8S-010` | Missing capabilities drop (`ALL`) | `securityContext:` `  allowPrivilegeEscalation: false` `  capabilities:` `    drop: ["ALL"]` |
| `K8S-011` | Host networking enabled | `spec:` `  hostNetwork: false` |
| `K8S-012` | Host PID namespace enabled | `spec:` `  hostPID: false` |
| `K8S-013` | Host IPC namespace enabled | `spec:` `  hostIPC: false` |
| `K8S-014` | Missing readOnlyRootFilesystem | `securityContext:` `  readOnlyRootFilesystem: true` |
| `K8S-015` | runAsNonRoot not enforced | `securityContext:` `  runAsNonRoot: true` |
| `K8S-016` | AppArmor profile not set | `metadata:` `  annotations:` `    container.apparmor.security.beta.kubernetes.io/app: runtime/default` |
| `K8S-017` | Seccomp profile Unconfined | `seccompProfile:` `  type: RuntimeDefault` |
| `K8S-018` | No liveness probe | `containers:` `- name: api` `  livenessProbe:` `    httpGet:` `      path: /healthz` |
| `K8S-019` | No readiness probe | `containers:` `- name: api` `  readinessProbe:` `    httpGet:` `      path: /ready` |
| `K8S-020` | No resource limits | `resources:` `  limits:` `    cpu: "500m"` `    memory: "512Mi"` |
| `K8S-021` | NetworkPolicy absent for namespace | `kind: NetworkPolicy` `metadata:` `  namespace: prod` `spec:` `  policyTypes: ["Ingress","Egress"]` |
| `K8S-022` | Service of type NodePort exposed by default | `kind: Service` `spec:` `  type: ClusterIP` |
| `K8S-023` | Wildcard RBAC verbs/resources | `verbs: ["get","list"]` `resources: ["pods"]` |
| `K8S-024` | automountServiceAccountToken enabled | `automountServiceAccountToken: false` |
| `K8S-025` | Latest image tag in workload | `image: org/api@sha256:abcd...` |
| `DOCK-010` | Container runs as root | `RUN adduser -D appuser` `USER appuser` |
| `DOCK-011` | Missing non-root USER in final stage | `FROM alpine:3.20` `USER 10001` `CMD ["app"]` |
| `DOCK-012` | Writable root filesystem by default | `docker run --read-only --tmpfs /tmp app@sha256:...` |
| `DOCK-013` | Base image uses latest tag | `FROM node:20.11.1@sha256:...` |
| `DOCK-014` | ADD used for remote URL | `COPY app.tar.gz /opt/` |
| `DOCK-015` | Package manager cache not cleaned | `RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*` |
| `DOCK-016` | Sensitive values in ENV/ARG | `ARG API_TOKEN` `# inject via runtime secrets` |
| `DOCK-017` | No HEALTHCHECK instruction | `Container Reliability` |
| `DOCK-018` | Privileged container run flags | `docker run --cap-drop ALL --security-opt no-new-privileges app:1.0` |
| `DOCK-019` | Docker socket mounted into container | `# do not mount docker.sock` |
| `DOCK-020` | No seccomp profile at runtime | `docker run --security-opt seccomp=default.json app:1.0` |
| `NGX-001` | HSTS header missing | `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;` |
| `NGX-002` | Content-Security-Policy missing | `add_header Content-Security-Policy "default-src 'self'" always;` |
| `NGX-003` | X-Content-Type-Options missing | `add_header X-Content-Type-Options "nosniff" always;` |
| `NGX-004` | X-Frame-Options missing | `add_header X-Frame-Options "DENY" always;` |
| `NGX-005` | Weak TLS protocols enabled | `ssl_protocols TLSv1.2 TLSv1.3;` |
| `NGX-006` | TLS 1.3 not enforced for strict profile | `ssl_protocols TLSv1.3;` |
| `NGX-007` | No request rate limiting | `limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;` |
| `NGX-008` | Client body size unlimited | `client_max_body_size 10m;` |
| `NGX-009` | Proxy timeouts missing | `proxy_connect_timeout 5s; proxy_read_timeout 30s;` |
| `NGX-010` | server_tokens enabled | `server_tokens off;` |
| `SQD-001` | HTTP egress proxy allows all clients | `http_access deny all` `http_access allow localnet` |
| `SQD-002` | Egress proxy cache_peer uses plaintext HTTP | `cache_peer upstream.example parent 3129 0 no-query tls` |
| `SQD-003` | ssl_bump without certificate validation policy | `sslproxy_cert_error deny all` |
| `SQD-004` | Weak ACL for CONNECT methods | `acl SSL_ports port 443` |
| `SQD-005` | No request rate/connection controls | `maxconn 100` |
| `SQD-006` | Access logs disabled | `access_log stdio:/var/log/squid/access.log` |
| `SQD-007` | Unsafe refresh_pattern wildcard | `Cache control security` |
| `SQD-008` | DNS over insecure resolver | `dns_nameservers 10.0.0.53` |
| `SQD-009` | Proxy auth not required for sensitive egress | `auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd` |
| `SQD-010` | No domain allowlist on egress | `acl allowed_domains dstdomain .corp.local` `http_access allow allowed_domains` |
| `SQD-011` | Unsafe forwarded_for policy | `forwarded_for transparent` |
| `SQD-012` | Insecure cache_dir permissions | `cache_effective_user squid` `cache_effective_group squid` |
| `SQD-013` | No denylist for metadata endpoints | `acl cloud_meta dst 169.254.169.254/32` `http_access deny cloud_meta` |
| `SQD-014` | HTTP egress proxy final deny rule missing / overly broad localnet ACL | Завершать ACL цепочку `http_access deny all` и ограничивать `localnet` только доверенными CIDR-сетями. |
| `NGX-011` | Nginx request limiting zone missing (`limit_req_zone`) | Добавить `limit_req_zone` с разумным rate/burst и применять `limit_req` на чувствительных location. |
| `NGX-012` | Nginx version disclosure via missing `server_tokens off` | Отключить `server_tokens`, скрывать версию веб-сервера и минимизировать fingerprinting surface. |
| `DOCK-021` | Docker base image uses mutable `latest` tag (`FROM ...:latest`) | Пиновать base image на конкретную версию и digest (`FROM python:3.12.3@sha256:...`) для воспроизводимости и supply-chain контроля. |
| `DOCK-022` | Unpinned `apt-get install` packages in Dockerfile | Фиксировать версии пакетов (`curl=... openssl=...`), использовать `--no-install-recommends` и очищать apt cache. |
| `INF-015` | Unintended proxy path allows access to internal K8s endpoints (CWE-441) | Блокировать proxy к internal ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254`) и использовать strict upstream allowlist. |
| `INF-016` | Helm chart defaults privileged pod/container security context (CWE-1188) | Дефолтно выставлять безопасные значения (`privileged: false`, `allowPrivilegeEscalation: false`, `runAsNonRoot: true`). |
| `INF-017` | Helm chart default enables host namespace sharing (CWE-1188) | По умолчанию отключать host namespaces и разрешать их только explicit opt-in с security review. |
| `INF-018` | Helm default grants broad capabilities without drop-all baseline (CWE-1188) | В chart defaults задавать `drop: ["ALL"]` и точечно добавлять только необходимые capabilities. |
| `NGX-013` | Nginx forward proxy behavior enables unintended internal routing (CWE-441) | Запретить dynamic upstream от пользовательских заголовков, фиксировать upstreams и блокировать internal dns zones/cluster domains. |
| `SQD-015` | HTTP egress proxy ACL permits proxying to Kubernetes control-plane/internal services (CWE-441) | Добавить explicit deny ACL для `*.svc`, control-plane IPs и metadata endpoints перед allow rules. |
| `K8S-026` | Helm values default `automountServiceAccountToken: true` for all workloads (CWE-1188) | Устанавливать default `false` и включать токен только для конкретных сервисов, где это необходимо. |
| `DOCK-023` | Docker: `docker load` образа без проверки подписи Cosign (CWE-347) | Подпись артефакта в registry; SBOM + verify в pipeline. |
| `DOCK-024` | Dockerfile: `FROM` без проверки digest при pull в CI (CWE-347) | `FROM repo/img@sha256:...` + verify attestation. |
| `DOCK-025` | Docker Compose pull без trust policy (CWE-347) | Подписанные образы и политика deploy only if verified. |
| `K8S-027` | Helm: `helm install` без `--verify` provenance (CWE-347) | Helm provenance + GPG/cosign для chart packages. |
| `K8S-028` | Helm: `values.yaml` с `image: tag` без digest и без policy (CWE-347) | OCI artifact signing + Kyborio/OPA policy. |

## Verification

**Verification:** Check the gold testbed file(s) below for `Vulnerable: <ID>` markers (static Semgrep + `detection-matrix.md` ground truth).

- [`gold-standard-testbed/infra_vulnerable.yaml`](../gold-standard-testbed/infra_vulnerable.yaml)
- [`gold-standard-testbed/Dockerfile`](../gold-standard-testbed/Dockerfile)
- [`gold-standard-testbed/nginx.conf`](../gold-standard-testbed/nginx.conf)

**Optional HTTP integration tests** (pytest + httpx; require a running API, `HEXVIBE_TARGET_URL`): [`gold-standard-testbed/integration/verify_infra_k8s_helm_poc.py`](../gold-standard-testbed/integration/verify_infra_k8s_helm_poc.py). See [`gold-standard-testbed/integration/README.md`](../gold-standard-testbed/integration/README.md).

After changing [`patterns.md`](patterns.md), run from the repo root:

```bash
python scripts/sync_semgrep.py
```

## Workflow: Recon → Scan → Verify

### 1) Recon
- Map entrypoints, data flows, and trust boundaries for this stack.
- Identify which metrics in [`patterns.md`](patterns.md) apply to the code under review.

### 2) Scan
- Run Semgrep with `semgrep-rules/<skill>.yaml` (generated) and correlate with Anti-Patterns.
- Eliminate findings that cannot bind to a metric row.

### 3) Verify
- Confirm markers or scanner hits for touched IDs in the gold testbed when adding metrics.
- Emit findings as `Vulnerable: <PREFIX>-<NNN>` in written reviews.

