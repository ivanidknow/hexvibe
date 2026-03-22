"""
Lightweight orchestration checks for HexVibe skill routing.

Run:
  python scripts/test_orchestration.py
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.adapter import list_skills_impl, select_skills_for_context


def _assert_top(file_path: str, file_content: str, question: str, expected: str) -> None:
    ranked = select_skills_for_context(file_path=file_path, file_content=file_content, question=question, top_k=5)
    if not ranked:
        raise AssertionError(f"No skills selected for {file_path}")
    top = ranked[0]["skill_id"]
    if top != expected:
        raise AssertionError(f"Expected top skill {expected}, got {top}. Ranked={ranked}")


def test_tie_break_priority() -> None:
    """
    Simulate conflict ru-regulatory vs common-security on one file and
    verify regulatory domain wins by security_priority.
    """
    common_dir = ROOT / "core" / "skills" / "common-security"
    common_dir.mkdir(parents=True, exist_ok=True)
    skill_json = common_dir / "skill.json"
    try:
        skill_json.write_text(
            json.dumps(
                {
                    "skill_id": "common-security",
                    "name": "Common Security",
                    "activation_triggers": ["common-security-marker"],
                    "relevant_extensions": [".bsl"],
                    "tools": ["semgrep", "syft", "trufflehog"],
                    "rules_path": "core/skills/common-security/patterns.md",
                    "few_shot_examples": "core/gold-standard-testbed/api_vulnerable.py",
                    "security_priority": 7,
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        ranked = select_skills_for_context(
            file_path="erp/exchange/event_handler.bsl",
            file_content="rrc-152fz-pdn common-security-marker",
            question="",
            top_k=5,
        )
        if not ranked:
            raise AssertionError("Tie-break test: no skills selected")
        if ranked[0]["skill_id"] != "ru-regulatory":
            raise AssertionError(f"Tie-break failed, top skill must be ru-regulatory. Ranked={ranked}")
    finally:
        shutil.rmtree(common_dir, ignore_errors=True)


def main() -> None:
    # Ensure trigger uniqueness (no exact duplicate trigger strings across skills).
    skills = list_skills_impl()["skills"]
    seen: dict[str, str] = {}
    for s in skills:
        sid = s["skill_id"]
        for trig in s.get("activation_triggers", []):
            if trig in seen:
                raise AssertionError(f"Duplicate trigger {trig!r} in {sid} and {seen[trig]}")
            seen[trig] = sid

    # Case 1: cloud metadata / vault leak in Python.
    _assert_top(
        file_path="src/cloud/worker.py",
        file_content='requests.get("http://169.254.169.254/latest/meta-data/")\nvault_token = "s.xxxxx"',
        question="Need to block sec-imds-169254 and vault access",
        expected="cloud-secrets",
    )

    # Case 2: RU regulatory / ПДн in 1С file.
    _assert_top(
        file_path="erp/integration/handler.bsl",
        file_content="rrc-152fz-pdn\nПДн клиента пишутся в лог",
        question="Как обрабатывать ПДн в 1С по требованиям 152-ФЗ?",
        expected="ru-regulatory",
    )

    # Case 3: Desktop VSTO / NSIS.
    _assert_top(
        file_path="installer/setup.nsi",
        file_content='!include "MUI2.nsh"\nins-nsis-installer',
        question="Need desktop office installer hardening",
        expected="hexvibe-desktop-vsto",
    )

    # Case 4: License compliance / syft.
    _assert_top(
        file_path="deps/requirements.txt",
        file_content="agpl-package==1.2.3\nlic-sbom-syft",
        question="Need SBOM and copyleft control",
        expected="license-compliance",
    )

    test_tie_break_priority()

    print("PASS: orchestration selects expected skills only")


if __name__ == "__main__":
    main()
