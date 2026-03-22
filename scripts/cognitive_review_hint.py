#!/usr/bin/env python3
"""
LLM / human review helper for HexVibe v1.0 Cognitive Security Review.

Prints the mandated self-critique subtask to pair with run_check findings.
"""

PROMPT = """
[HexVibe v1.0 — Self-critique subtask]
For each candidate vulnerability:
1) Try to disprove it: list preconditions that would make it non-exploitable.
2) If impact depends on environment variables, feature flags, or missing attacker control, cap severity at LOW.
3) Prefer taint/data-flow evidence over single-line literal matches; flag static constants as lower confidence.
"""


def main() -> int:
    print(PROMPT.strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
