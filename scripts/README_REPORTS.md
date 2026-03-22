# Reports and MCP Sync

Use these commands from the repository root to keep reports and MCP runtime aligned.

## 1) Regenerate full Fortress remediation report

```bash
python3 scripts/generate_full_500_report.py
```

This command rebuilds `core/gold-standard-testbed/run-check-remediation-report.md` with all 500 IDs and full Safe-Patterns.

## 2) Rebuild and refresh MCP Docker server

```bash
bash scripts/docker-publish.sh
```

This command rebuilds `hexvibe-ai:latest`, runs internal health checks, and refreshes the runtime bundle used by MCP clients.
