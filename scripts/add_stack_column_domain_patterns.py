from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "core" / "skills"

ROW_RE_5 = re.compile(
    r"^\|\s*(?P<id>[A-Z0-9]{2,4}-[0-9A-Za-z.\-]+)\s*\|"
    r"\s*(?P<title>.*?)\s*\|"
    r"\s*(?P<anti>.*?)\s*\|"
    r"\s*(?P<safe>.*?)\s*\|"
    r"\s*(?P<source>.*?)\s*\|"
    r"(?P<tail>\s*<!--.*?-->\s*)?$"
)

ROW_RE_6 = re.compile(
    r"^\|\s*(?P<id>[A-Z0-9]{2,4}-[0-9A-Za-z.\-]+)\s*\|"
    r"\s*(?P<title>.*?)\s*\|"
    r"\s*(?P<anti>.*?)\s*\|"
    r"\s*(?P<safe>.*?)\s*\|"
    r"\s*(?P<stack>.*?)\s*\|"
    r"\s*(?P<source>.*?)\s*\|"
    r"(?P<tail>\s*<!--.*?-->\s*)?$"
)

VALID_STACKS = {
    "Python",
    "Python/FastAPI",
    "Node.js/JavaScript",
    "Node.js/NestJS",
    "Go",
    "Flutter",
    "Electron/Desktop",
    "Electron/Desktop/.NET",
    ".NET/C#",
    "Kubernetes/Infra",
    "Compliance/Regulatory",
    "Compliance/License",
    "Identity/OIDC",
    "Cloud/Secrets",
    "Agent/Browser",
    "Browser Automation",
    "Observability",
    "Integration/API",
    "DevOps/Supply Chain",
    "Application Logic",
    "Application",
    "Platform/API",
    "Ruby/Rails",
    "Java/Spring",
    "Generic",
}


def is_valid_stack(value: str) -> bool:
    v = value.strip()
    if not v:
        return False
    if v in VALID_STACKS:
        return True
    if len(v) > 40:
        return False
    if any(token in v for token in ["`", "<", ">", ":", "{", "}", "@app", "return ", "None = None"]):
        return False
    return False


def infer_stack(metric_id: str, title: str, anti: str, safe: str, source: str, skill_name: str) -> str:
    text = " ".join([metric_id, title, anti, safe, source]).lower()
    skill = skill_name.lower()
    if "go-core" in skill:
        return "Go"
    if "java-spring" in skill:
        return "Java/Spring"
    if "ruby-rails" in skill:
        return "Ruby/Rails"
    if "csharp-dotnet" in skill:
        return ".NET/C#"
    if "infra-k8s-helm" in skill:
        return "Kubernetes/Infra"
    if "ru-regulatory" in skill:
        return "Compliance/Regulatory"
    if "auth-keycloak" in skill:
        return "Identity/OIDC"
    if "cloud-secrets" in skill:
        return "Cloud/Secrets"
    if "desktop-vsto-suite" in skill:
        return "Electron/Desktop/.NET"
    if "nodejs-nestjs" in skill:
        return "Node.js/NestJS"
    if "advanced-agent-cloud" in skill:
        return "Agent/Browser"
    if "browser-agent" in skill:
        return "Browser Automation"
    if "observability" in skill:
        return "Observability"
    if "fastapi-async" in skill:
        return "Python/FastAPI"
    if "license-compliance" in skill:
        return "Compliance/License"
    if "integration-security" in skill:
        return "Integration/API"
    if "devops-security" in skill:
        return "DevOps/Supply Chain"
    if "app-logic" in skill:
        return "Application Logic"
    if "domain-" in skill:
        # Keep richer metric-based mapping for consolidated domain skills.
        pass
    if metric_id.startswith(("PY-", "DJA-", "FAS-")):
        return "Python"
    if metric_id.startswith(("NJS-", "NST-", "FTS-")):
        return "Node.js/JavaScript"
    if metric_id.startswith("GO-"):
        return "Go"
    if metric_id.startswith("MOB-"):
        return "Flutter"
    if metric_id.startswith(("DSK-", "INS-")):
        return "Electron/Desktop"
    if metric_id.startswith(("K8S-", "DOCK-", "NGX-", "SQD-", "INF-")):
        return "Kubernetes/Infra"
    if metric_id.startswith(("RRC-", "LIC-", "AK-")):
        return "Compliance/Identity"
    if metric_id.startswith("APP-"):
        if any(k in text for k in ["timeout", "retry", "circuit"]):
            return "Platform/API"
        return "Application"
    if metric_id.startswith("LOG-"):
        return "Observability"
    return "Generic"


def update_file(path: Path) -> int:
    skill_name = path.parent.name
    lines = path.read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    updated = 0

    for line in lines:
        if line.strip() == "| ID | Название метрики | Anti-Pattern (Vulnerable Code/YAML) | Safe-Pattern (Remediation) | Источник |":
            out.append(
                "| ID | Название метрики | Anti-Pattern (Vulnerable Code/YAML) | Safe-Pattern (Remediation) | Stack | Источник |"
            )
            continue
        if line.strip() == "|---|---|---|---|---|":
            out.append("|---|---|---|---|---|---|")
            continue

        m6 = ROW_RE_6.match(line)
        if m6:
            gd = m6.groupdict()
            inferred = infer_stack(gd["id"], gd["title"], gd["anti"], gd["safe"], gd["source"], skill_name)
            raw_stack = gd["stack"].strip()
            stack = raw_stack if is_valid_stack(raw_stack) else inferred
            tail = gd.get("tail") or ""
            out.append(
                f"| {gd['id'].strip()} | {gd['title'].strip()} | {gd['anti'].strip()} | {gd['safe'].strip()} | {stack} | {gd['source'].strip()} |{tail}"
            )
            updated += 1
            continue

        m5 = ROW_RE_5.match(line)
        if m5:
            gd = m5.groupdict()
            stack = infer_stack(gd["id"], gd["title"], gd["anti"], gd["safe"], gd["source"], skill_name)
            tail = gd.get("tail") or ""
            out.append(
                f"| {gd['id'].strip()} | {gd['title'].strip()} | {gd['anti'].strip()} | {gd['safe'].strip()} | {stack} | {gd['source'].strip()} |{tail}"
            )
            updated += 1
            continue

        out.append(line)

    path.write_text("\n".join(out) + "\n", encoding="utf-8")
    return updated


def main() -> None:
    for path in sorted(SKILLS.glob("*/patterns.md")):
        count = update_file(path)
        print(f"{path.relative_to(ROOT)}: updated_rows={count}")


if __name__ == "__main__":
    main()
