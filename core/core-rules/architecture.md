# HexVibe Architecture Principles

## Security and Compliance Baseline

1. AGPL licensed dependencies are prohibited in all layers of the platform.
2. All asynchronous SQLAlchemy calls must be explicitly validated for missing `await` usage.
3. `privileged: false` must be enforced in all Docker and Kubernetes configurations. # Fix: Changed according to INF-5.2.1
4. `USER root` is forbidden in Docker images and runtime configurations.

