from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "core" / "skills"

SOURCE_SKILLS = [
    "python-backend-pro",
    "python-security",
    "python-django",
    "mobile-flutter",
    "desktop-electron-pro",
    "nodejs-security",
    "frontend-security",
]

TARGETS = {
    "access": SKILLS / "domain-access-management" / "patterns.md",
    "privacy": SKILLS / "domain-data-privacy" / "patterns.md",
    "platform": SKILLS / "domain-platform-hardening" / "patterns.md",
    "input": SKILLS / "domain-input-validation" / "patterns.md",
}

ROW_RE = re.compile(
    r"^\|\s*([A-Z0-9]{2,4}-[0-9][0-9A-Za-z.\-]*)\s*\|"
    r"\s*(.*?)\s*\|\s*(.*?)\s*\|\s*(.*?)\s*\|\s*(.*?)\s*\|(?:\s*<!--.*?-->)?\s*$"
)


def parse_rows(path: Path) -> list[tuple[str, str, str, str, str]]:
    out: list[tuple[str, str, str, str, str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        m = ROW_RE.match(line)
        if m:
            out.append((m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)))
    return out


def pick_bucket(title: str, anti: str, safe: str, source: str) -> str:
    s = " ".join([title, anti, safe, source]).lower()
    if any(k in s for k in ["auth", "jwt", "session", "bola", "idor", "role", "token", "mfa", "queryset", "owner"]):
        return "access"
    if any(k in s for k in ["log", "pii", "privacy", "console", "trace", "error", "snils", "source map", "secret"]):
        return "privacy"
    if any(
        k in s
        for k in [
            "flutter",
            "electron",
            "k8s",
            "docker",
            "xlsx",
            "flag_secure",
            "platform",
            "resource",
            "probe",
            "networkpolicy",
            "tls",
        ]
    ):
        return "platform"
    return "input"


def main() -> None:
    existing = {k: {row[0] for row in parse_rows(v)} for k, v in TARGETS.items()}
    adds: dict[str, list[tuple[str, str, str, str, str]]] = {k: [] for k in TARGETS}

    for name in SOURCE_SKILLS:
        src = SKILLS / name / "patterns.md"
        if not src.exists():
            continue
        for rid, title, anti, safe, source in parse_rows(src):
            bucket = pick_bucket(title, anti, safe, source)
            if rid not in existing[bucket]:
                adds[bucket].append((rid, title, anti, safe, source))
                existing[bucket].add(rid)

    for bucket, path in TARGETS.items():
        if not adds[bucket]:
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for rid, title, anti, safe, source in adds[bucket]:
            lines.append(f"| {rid} | {title} | {anti} | {safe} | {source} |")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"{bucket}: +{len(adds[bucket])}")


if __name__ == "__main__":
    main()
