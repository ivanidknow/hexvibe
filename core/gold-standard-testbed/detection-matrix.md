# HexVibe detection matrix

**Total rules:** 9489 (generated from `semgrep-rules/*.yaml`)

A row is **HIT** when Semgrep reports the rule *or* a `Vulnerable: <ID>` marker exists in the gold testbed (structural patterns may be skipped if the first `pattern-either` branch fails to parse).

| ID | File (Vulnerable marker) | Status | Evidence |
|---|---|---|---|
| AAC-001 | `core/gold-standard-testbed/aac_vulnerable.py` | HIT | Semgrep + marker |
| AAC-002 | `core/gold-standard-testbed/aac_vulnerable.py` | HIT | Semgrep + marker |
| AAC-003 | `core/gold-standard-testbed/aac_vulnerable.ts` | HIT | Marker (testbed) |
| AAC-004 | `core/gold-standard-testbed/aac_vulnerable.py` | HIT | Semgrep + marker |
| AAC-005 | `core/gold-standard-testbed/aac_vulnerable.py` | HIT | Marker (testbed) |
| AAC-006 | `core/gold-standard-testbed/aac_vulnerable.py` | HIT | Marker (testbed) |
| AAC-007 | `core/gold-standard-testbed/aac_vulnerable.py` | HIT | Semgrep + marker |
| AAC-008 | `core/gold-standard-testbed/aac_vulnerable.py` | HIT | Semgrep + marker |
| AAC-009 | `core/gold-standard-testbed/aac_vulnerable.py` | HIT | Semgrep + marker |
| AAC-010 | `core/gold-standard-testbed/aac_vulnerable.ts` | HIT | Semgrep + marker |
| AAC-011 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| AAC-012 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| AAC-013 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| AAC-014 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| AAC-015 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| AAC-016 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| AAC-017 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| AAC-018 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| AAC-019 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| AAC-020 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| AAC-021 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| AAC-022 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| AAC-023 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| AAC-024 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| AAC-025 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| AAC-026 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| AAC-027 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| AAC-028 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| AAC-029 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| AAC-030 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| AAC-031 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| AAC-032 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| AAC-033 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| AAC-034 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| AAC-035 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| AAC-036 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| AAC-037 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| AAC-038 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| AAC-039 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| AAC-040 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| AAC-041 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| AAC-042 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| AAC-043 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| AAC-044 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| AGT-001 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-002 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-003 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-004 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-005 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-006 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-007 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-008 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-009 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-010 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-011 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-012 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-013 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-014 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-015 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-016 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-017 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-018 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-019 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-020 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-021 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-022 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-023 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-024 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-025 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-026 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-027 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-028 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-029 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-030 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-031 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-032 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-033 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-034 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-035 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-036 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-037 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-038 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-039 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-040 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-041 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-042 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-043 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-044 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-045 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-046 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-047 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-048 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-049 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-050 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-051 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-052 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-053 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-054 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-055 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-056 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-057 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-058 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-059 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-060 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-061 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-062 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-063 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-064 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-065 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-066 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-067 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-068 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-069 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-070 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-071 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-072 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-073 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-074 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-075 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-076 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-077 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-078 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-079 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-080 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-081 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-082 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-083 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-084 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-085 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-086 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-087 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-088 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-089 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-090 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-091 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-092 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-093 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-094 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-095 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-096 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-097 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-098 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-099 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AGT-100 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| AI-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AI-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AI-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AI-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AI-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AI-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AI-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AI-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AI-009 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AI-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AI-011 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AI-012 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AI-013 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AI-014 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| AI-015 | `core/gold-standard-testbed/ai_generated_lazy_auth.go` | HIT | Marker (testbed) |
| AI-016 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AI-017 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AI-018 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AI-019 | `core/gold-standard-testbed/ai_generated_lazy_auth.go` | HIT | Marker (testbed) |
| AI-020 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AI-021 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AI-022 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AI-023 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AI-024 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AI-025 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AK-001 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| AK-002 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| AK-003 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| AK-004 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| AK-005 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| AK-006 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| AK-007 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| AK-008 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| AK-009 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| AK-010 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| AK-011 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| AK-012 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| AK-013 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| AK-014 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| AK-015 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| AK-016 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| AK-017 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Semgrep + marker |
| AK-018 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| AK-019 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Semgrep + marker |
| AK-020 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| AK-021 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| AK-022 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AK-023 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AK-024 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AK-025 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AK-026 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AK-027 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AK-028 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AK-029 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AK-030 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AK-031 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AK-032 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AK-033 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AK-034 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AK-035 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AK-036 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AK-037 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AK-038 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AK-039 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AK-040 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AK-041 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AK-042 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AK-043 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| AK-044 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| APP-100 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| APP-101 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| APP-102 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| APP-103 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| APP-104 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| APP-105 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| APP-106 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| APP-107 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| APP-108 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| APP-109 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| APP-110 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| APP-111 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| APP-112 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| APP-113 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| APP-114 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| APP-115 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| APP-116 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| APP-117 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| APP-118 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| APP-119 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| ASVS-AC-001 | `core/gold-standard-testbed/java/asvs/asvs_ac_001.java` | HIT | Marker (testbed) |
| ASVS-AC-002 | `core/gold-standard-testbed/java/asvs/asvs_ac_002.java` | HIT | Marker (testbed) |
| ASVS-AC-003 | `core/gold-standard-testbed/java/asvs/asvs_ac_003.java` | HIT | Marker (testbed) |
| ASVS-AC-004 | `core/gold-standard-testbed/java/asvs/asvs_ac_004.java` | HIT | Marker (testbed) |
| ASVS-AC-005 | `core/gold-standard-testbed/java/asvs/asvs_ac_005.java` | HIT | Marker (testbed) |
| ASVS-AC-006 | `core/gold-standard-testbed/java/asvs/asvs_ac_006.java` | HIT | Semgrep + marker |
| ASVS-AC-007 | `core/gold-standard-testbed/java/asvs/asvs_ac_007.java` | HIT | Marker (testbed) |
| ASVS-AC-008 | `core/gold-standard-testbed/java/asvs/asvs_ac_008.java` | HIT | Marker (testbed) |
| ASVS-AC-009 | `core/gold-standard-testbed/java/asvs/asvs_ac_009.java` | HIT | Marker (testbed) |
| ASVS-AC-010 | `core/gold-standard-testbed/java/asvs/asvs_ac_010.java` | HIT | Marker (testbed) |
| ASVS-API-001 | `core/gold-standard-testbed/java/asvs/asvs_api_001.java` | HIT | Marker (testbed) |
| ASVS-API-002 | `core/gold-standard-testbed/java/asvs/asvs_api_002.java` | HIT | Marker (testbed) |
| ASVS-API-003 | `core/gold-standard-testbed/java/asvs/asvs_api_003.java` | HIT | Marker (testbed) |
| ASVS-API-004 | `core/gold-standard-testbed/java/asvs/asvs_api_004.java` | HIT | Marker (testbed) |
| ASVS-API-005 | `core/gold-standard-testbed/java/asvs/asvs_api_005.java` | HIT | Semgrep + marker |
| ASVS-API-006 | `core/gold-standard-testbed/java/asvs/asvs_api_006.java` | HIT | Marker (testbed) |
| ASVS-API-007 | `core/gold-standard-testbed/java/asvs/asvs_api_007.java` | HIT | Marker (testbed) |
| ASVS-API-008 | `core/gold-standard-testbed/java/asvs/asvs_api_008.java` | HIT | Marker (testbed) |
| ASVS-API-009 | `core/gold-standard-testbed/java/asvs/asvs_api_009.java` | HIT | Semgrep + marker |
| ASVS-API-010 | `core/gold-standard-testbed/java/asvs/asvs_api_010.java` | HIT | Marker (testbed) |
| ASVS-API-011 | `core/gold-standard-testbed/java/asvs/asvs_api_011.java` | HIT | Marker (testbed) |
| ASVS-API-012 | `core/gold-standard-testbed/java/asvs/asvs_api_012.java` | HIT | Marker (testbed) |
| ASVS-API-013 | `core/gold-standard-testbed/java/asvs/asvs_api_013.java` | HIT | Marker (testbed) |
| ASVS-API-014 | `core/gold-standard-testbed/java/asvs/asvs_api_014.java` | HIT | Marker (testbed) |
| ASVS-API-015 | `core/gold-standard-testbed/java/asvs/asvs_api_015.java` | HIT | Marker (testbed) |
| ASVS-AUTH-001 | `core/gold-standard-testbed/java/asvs/asvs_auth_001.java` | HIT | Marker (testbed) |
| ASVS-AUTH-002 | `core/gold-standard-testbed/java/asvs/asvs_auth_002.java` | HIT | Marker (testbed) |
| ASVS-AUTH-003 | `core/gold-standard-testbed/java/asvs/asvs_auth_003.java` | HIT | Semgrep + marker |
| ASVS-AUTH-004 | `core/gold-standard-testbed/java/asvs/asvs_auth_004.java` | HIT | Marker (testbed) |
| ASVS-AUTH-005 | `core/gold-standard-testbed/java/asvs/asvs_auth_005.java` | HIT | Marker (testbed) |
| ASVS-AUTH-006 | `core/gold-standard-testbed/java/asvs/asvs_auth_006.java` | HIT | Semgrep + marker |
| ASVS-AUTH-007 | `core/gold-standard-testbed/java/asvs/asvs_auth_007.java` | HIT | Marker (testbed) |
| ASVS-AUTH-008 | `core/gold-standard-testbed/java/asvs/asvs_auth_008.java` | HIT | Marker (testbed) |
| ASVS-AUTH-009 | `core/gold-standard-testbed/java/asvs/asvs_auth_009.java` | HIT | Semgrep + marker |
| ASVS-AUTH-010 | `core/gold-standard-testbed/java/asvs/asvs_auth_010.java` | HIT | Semgrep + marker |
| ASVS-CONF-001 | `core/gold-standard-testbed/java/asvs/asvs_conf_001.java` | HIT | Marker (testbed) |
| ASVS-CONF-002 | `core/gold-standard-testbed/java/asvs/asvs_conf_002.java` | HIT | Marker (testbed) |
| ASVS-CONF-003 | `core/gold-standard-testbed/java/asvs/asvs_conf_003.java` | HIT | Marker (testbed) |
| ASVS-CONF-004 | `core/gold-standard-testbed/java/asvs/asvs_conf_004.java` | HIT | Marker (testbed) |
| ASVS-CONF-005 | `core/gold-standard-testbed/java/asvs/asvs_conf_005.java` | HIT | Marker (testbed) |
| ASVS-CONF-006 | `core/gold-standard-testbed/java/asvs/asvs_conf_006.java` | HIT | Marker (testbed) |
| ASVS-CONF-007 | `core/gold-standard-testbed/java/asvs/asvs_conf_007.java` | HIT | Marker (testbed) |
| ASVS-CONF-008 | `core/gold-standard-testbed/java/asvs/asvs_conf_008.java` | HIT | Marker (testbed) |
| ASVS-CONF-009 | `core/gold-standard-testbed/java/asvs/asvs_conf_009.java` | HIT | Semgrep + marker |
| ASVS-CONF-010 | `core/gold-standard-testbed/java/asvs/asvs_conf_010.java` | HIT | Marker (testbed) |
| ASVS-FILE-001 | `core/gold-standard-testbed/java/asvs/asvs_file_001.java` | HIT | Marker (testbed) |
| ASVS-FILE-002 | `core/gold-standard-testbed/java/asvs/asvs_file_002.java` | HIT | Marker (testbed) |
| ASVS-FILE-003 | `core/gold-standard-testbed/java/asvs/asvs_file_003.java` | HIT | Marker (testbed) |
| ASVS-FILE-004 | `core/gold-standard-testbed/java/asvs/asvs_file_004.java` | HIT | Marker (testbed) |
| ASVS-FILE-005 | `core/gold-standard-testbed/java/asvs/asvs_file_005.java` | HIT | Marker (testbed) |
| ASVS-FILE-006 | `core/gold-standard-testbed/java/asvs/asvs_file_006.java` | HIT | Marker (testbed) |
| ASVS-FILE-007 | `core/gold-standard-testbed/java/asvs/asvs_file_007.java` | HIT | Marker (testbed) |
| ASVS-FILE-008 | `core/gold-standard-testbed/java/asvs/asvs_file_008.java` | HIT | Marker (testbed) |
| ASVS-FILE-009 | `core/gold-standard-testbed/java/asvs/asvs_file_009.java` | HIT | Marker (testbed) |
| ASVS-FILE-010 | `core/gold-standard-testbed/java/asvs/asvs_file_010.java` | HIT | Marker (testbed) |
| ASVS-FILE-011 | `core/gold-standard-testbed/java/asvs/asvs_file_011.java` | HIT | Marker (testbed) |
| ASVS-FILE-012 | `core/gold-standard-testbed/java/asvs/asvs_file_012.java` | HIT | Marker (testbed) |
| ASVS-FILE-013 | `core/gold-standard-testbed/java/asvs/asvs_file_013.java` | HIT | Marker (testbed) |
| ASVS-FILE-014 | `core/gold-standard-testbed/java/asvs/asvs_file_014.java` | HIT | Marker (testbed) |
| ASVS-FILE-015 | `core/gold-standard-testbed/java/asvs/asvs_file_015.java` | HIT | Marker (testbed) |
| ASVS-LOG-001 | `core/gold-standard-testbed/java/asvs/asvs_log_001.java` | HIT | Marker (testbed) |
| ASVS-LOG-002 | `core/gold-standard-testbed/java/asvs/asvs_log_002.java` | HIT | Marker (testbed) |
| ASVS-LOG-003 | `core/gold-standard-testbed/java/asvs/asvs_log_003.java` | HIT | Marker (testbed) |
| ASVS-LOG-004 | `core/gold-standard-testbed/java/asvs/asvs_log_004.java` | HIT | Marker (testbed) |
| ASVS-LOG-005 | `core/gold-standard-testbed/java/asvs/asvs_log_005.java` | HIT | Marker (testbed) |
| ASVS-LOG-006 | `core/gold-standard-testbed/java/asvs/asvs_log_006.java` | HIT | Marker (testbed) |
| ASVS-LOG-007 | `core/gold-standard-testbed/java/asvs/asvs_log_007.java` | HIT | Marker (testbed) |
| ASVS-LOG-008 | `core/gold-standard-testbed/java/asvs/asvs_log_008.java` | HIT | Marker (testbed) |
| ASVS-LOG-009 | `core/gold-standard-testbed/java/asvs/asvs_log_009.java` | HIT | Marker (testbed) |
| ASVS-LOG-010 | `core/gold-standard-testbed/java/asvs/asvs_log_010.java` | HIT | Marker (testbed) |
| ASVS-MAL-001 | `core/gold-standard-testbed/java/asvs/asvs_mal_001.java` | HIT | Marker (testbed) |
| ASVS-MAL-002 | `core/gold-standard-testbed/java/asvs/asvs_mal_002.java` | HIT | Marker (testbed) |
| ASVS-MAL-003 | `core/gold-standard-testbed/java/asvs/asvs_mal_003.java` | HIT | Marker (testbed) |
| ASVS-MAL-004 | `core/gold-standard-testbed/java/asvs/asvs_mal_004.java` | HIT | Marker (testbed) |
| ASVS-MAL-005 | `core/gold-standard-testbed/java/asvs/asvs_mal_005.java` | HIT | Marker (testbed) |
| ASVS-MAL-006 | `core/gold-standard-testbed/java/asvs/asvs_mal_006.java` | HIT | Marker (testbed) |
| ASVS-MAL-007 | `core/gold-standard-testbed/java/asvs/asvs_mal_007.java` | HIT | Marker (testbed) |
| ASVS-MAL-008 | `core/gold-standard-testbed/java/asvs/asvs_mal_008.java` | HIT | Marker (testbed) |
| ASVS-MAL-009 | `core/gold-standard-testbed/java/asvs/asvs_mal_009.java` | HIT | Marker (testbed) |
| ASVS-MAL-010 | `core/gold-standard-testbed/java/asvs/asvs_mal_010.java` | HIT | Marker (testbed) |
| ASVS-SESS-001 | `core/gold-standard-testbed/java/asvs/asvs_sess_001.java` | HIT | Semgrep + marker |
| ASVS-SESS-002 | `core/gold-standard-testbed/java/asvs/asvs_sess_002.java` | HIT | Semgrep + marker |
| ASVS-SESS-003 | `core/gold-standard-testbed/java/asvs/asvs_sess_003.java` | HIT | Semgrep + marker |
| ASVS-SESS-004 | `core/gold-standard-testbed/java/asvs/asvs_sess_004.java` | HIT | Semgrep + marker |
| ASVS-SESS-005 | `core/gold-standard-testbed/java/asvs/asvs_sess_005.java` | HIT | Semgrep + marker |
| ASVS-SESS-006 | `core/gold-standard-testbed/java/asvs/asvs_sess_006.java` | HIT | Marker (testbed) |
| ASVS-SESS-007 | `core/gold-standard-testbed/java/asvs/asvs_sess_007.java` | HIT | Semgrep + marker |
| ASVS-SESS-008 | `core/gold-standard-testbed/java/asvs/asvs_sess_008.java` | HIT | Semgrep + marker |
| ASVS-SESS-009 | `core/gold-standard-testbed/java/asvs/asvs_sess_009.java` | HIT | Semgrep + marker |
| ASVS-SESS-010 | `core/gold-standard-testbed/java/asvs/asvs_sess_010.java` | HIT | Marker (testbed) |
| ASVS-VAL-001 | `core/gold-standard-testbed/java/asvs/asvs_val_001.java` | HIT | Marker (testbed) |
| ASVS-VAL-002 | `core/gold-standard-testbed/java/asvs/asvs_val_002.java` | HIT | Marker (testbed) |
| ASVS-VAL-003 | `core/gold-standard-testbed/java/asvs/asvs_val_003.java` | HIT | Marker (testbed) |
| ASVS-VAL-004 | `core/gold-standard-testbed/java/asvs/asvs_val_004.java` | HIT | Marker (testbed) |
| ASVS-VAL-005 | `core/gold-standard-testbed/java/asvs/asvs_val_005.java` | HIT | Marker (testbed) |
| ASVS-VAL-006 | `core/gold-standard-testbed/java/asvs/asvs_val_006.java` | HIT | Marker (testbed) |
| ASVS-VAL-007 | `core/gold-standard-testbed/java/asvs/asvs_val_007.java` | HIT | Marker (testbed) |
| ASVS-VAL-008 | `core/gold-standard-testbed/java/asvs/asvs_val_008.java` | HIT | Marker (testbed) |
| ASVS-VAL-009 | `core/gold-standard-testbed/java/asvs/asvs_val_009.java` | HIT | Marker (testbed) |
| ASVS-VAL-010 | `core/gold-standard-testbed/java/asvs/asvs_val_010.java` | HIT | Marker (testbed) |
| BIZ-001 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| BIZ-002 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| BIZ-003 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| BIZ-004 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Semgrep + marker |
| BIZ-005 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| BIZ-006 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| BIZ-007 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| BIZ-008 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| BIZ-009 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| BIZ-010 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| BIZ-011 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| BIZ-012 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| BIZ-013 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| BIZ-014 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| BIZ-015 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| BIZ-016 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| BIZ-017 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| BIZ-018 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| BIZ-019 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| BIZ-020 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-021 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-022 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-023 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| BIZ-024 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| BIZ-025 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-026 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-027 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-028 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-029 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-030 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-031 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-032 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-033 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-034 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-035 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-036 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-037 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-038 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-039 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-040 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-041 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-042 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-043 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-044 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-045 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-046 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-047 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-048 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-049 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-050 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-051 | `core/gold-standard-testbed/api_verbosity_leak.java` | HIT | Marker (testbed) |
| BIZ-052 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-053 | `core/gold-standard-testbed/api_verbosity_leak.java` | HIT | Marker (testbed) |
| BIZ-054 | `core/gold-standard-testbed/api_verbosity_leak.java` | HIT | Marker (testbed) |
| BIZ-055 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-056 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| BIZ-057 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| BIZ-058 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-059 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-060 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-061 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-062 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-063 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-064 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-065 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-066 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| BIZ-067 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-068 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-069 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-070 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BIZ-071 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| BRW-001 | `core/gold-standard-testbed/browser_vulnerable.js` | HIT | Marker (testbed) |
| BRW-002 | `core/gold-standard-testbed/browser_vulnerable.js` | HIT | Marker (testbed) |
| BRW-003 | `core/gold-standard-testbed/browser_vulnerable.js` | HIT | Marker (testbed) |
| BRW-004 | `core/gold-standard-testbed/browser_vulnerable.js` | HIT | Semgrep + marker |
| BRW-005 | `core/gold-standard-testbed/browser_vulnerable.js` | HIT | Marker (testbed) |
| BRW-006 | `core/gold-standard-testbed/browser_vulnerable.js` | HIT | Marker (testbed) |
| BRW-007 | `core/gold-standard-testbed/browser_vulnerable.js` | HIT | Marker (testbed) |
| BRW-008 | `core/gold-standard-testbed/browser_vulnerable.js` | HIT | Marker (testbed) |
| BRW-009 | `core/gold-standard-testbed/browser_vulnerable.js` | HIT | Marker (testbed) |
| BRW-010 | `core/gold-standard-testbed/browser_vulnerable.js` | HIT | Marker (testbed) |
| BRW-011 | `core/gold-standard-testbed/browser_vulnerable.js` | HIT | Marker (testbed) |
| BRW-012 | `core/gold-standard-testbed/browser_vulnerable.js` | HIT | Semgrep + marker |
| BRW-013 | `core/gold-standard-testbed/browser_vulnerable.js` | HIT | Marker (testbed) |
| CAC-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CAC-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CAC-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CAC-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CAC-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CAC-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CAC-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CAC-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CAC-009 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CAC-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CAC-011 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CAC-012 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CAC-013 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CAC-014 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CAC-015 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CAM-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CAM-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CAM-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CAM-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CAM-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| CAM-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CAM-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| CAM-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| CAM-009 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| CAM-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| CAM-011 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| CAM-012 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| CAM-013 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CAM-014 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CAM-015 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| CAM-016 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CAM-017 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| CAM-018 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| CAM-019 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CAM-020 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| CAM-021 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| CAM-022 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| CAM-023 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| CAM-024 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| CAM-025 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CAM-026 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CAM-027 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| CAM-028 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| CAM-029 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| CAM-030 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| CIC-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CIC-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CIC-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CIC-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CIC-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CIC-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CIC-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CIC-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CIC-009 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CIC-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CLD-001 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-002 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-003 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-004 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-005 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-006 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-007 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-008 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-009 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-010 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-011 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-012 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-013 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-014 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-015 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-016 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-017 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-018 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-019 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-020 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-021 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-022 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-023 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-024 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-025 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-026 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-027 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-028 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-029 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-030 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-031 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-032 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-033 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-034 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-035 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-036 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-037 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-038 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-039 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-040 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-041 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-042 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-043 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-044 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-045 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-046 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-047 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-048 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-049 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-050 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-051 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-052 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-053 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-054 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-055 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-056 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-057 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-058 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-059 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-060 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-061 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-062 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-063 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-064 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-065 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-066 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-067 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-068 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-069 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-070 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-071 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-072 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-073 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-074 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-075 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-076 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-077 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-078 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-079 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-080 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-081 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-082 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-083 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-084 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-085 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-086 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-087 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-088 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-089 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-090 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-091 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-092 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-093 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-094 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-095 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-096 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-097 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-098 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-099 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-100 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-101 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-102 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-103 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-104 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-105 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-106 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-107 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-108 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-109 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-110 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-111 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-112 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-113 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-114 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-115 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-116 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-117 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-118 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-119 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-120 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-121 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-122 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-123 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-124 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-125 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-126 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-127 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-128 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-129 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-130 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-131 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-132 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-133 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-134 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-135 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-136 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-137 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-138 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-139 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-140 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-141 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-142 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-143 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-144 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-145 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-146 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-147 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-148 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-149 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CLD-150 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| CRA-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| CRA-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRA-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRA-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRA-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRA-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRA-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRA-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRA-009 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRA-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRA-011 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRA-012 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRA-013 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRA-014 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRA-015 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRA-016 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRA-017 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRA-018 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRA-019 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRA-020 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| CRY-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| CRY-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| CRY-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-009 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-011 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-012 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-013 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-014 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-015 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-016 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-017 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-018 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-019 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-020 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-021 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-022 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-023 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-024 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-025 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-026 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-027 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-028 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-029 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-030 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-031 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-032 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-033 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| CRY-034 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-035 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-036 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-037 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-038 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-039 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-040 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-041 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-042 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-043 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-044 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-045 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-046 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-047 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-048 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-049 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CRY-050 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| CSH-001 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-002 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-003 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-004 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-005 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-006 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-007 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-008 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-009 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-010 | `core/gold-standard-testbed/multi_lang_vulnerable/csharp_vulnerable.cs` | HIT | Semgrep + marker |
| CSH-011 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-012 | `core/gold-standard-testbed/multi_lang_vulnerable/csharp_vulnerable.cs` | HIT | Semgrep + marker |
| CSH-013 | `core/gold-standard-testbed/multi_lang_vulnerable/csharp_vulnerable.cs` | HIT | Semgrep + marker |
| CSH-014 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-015 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-016 | `core/gold-standard-testbed/multi_lang_vulnerable/csharp_vulnerable.cs` | HIT | Semgrep + marker |
| CSH-017 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CSH-018 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CSH-019 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CSH-020 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CSH-021 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CSH-022 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CSH-023 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-024 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CSH-025 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CSH-026 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-027 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-028 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CSH-029 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-030 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-031 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-032 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-033 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-034 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-035 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-036 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CSH-037 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CSH-038 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-039 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-040 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-041 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-042 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-043 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CSH-044 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-045 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-046 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-047 | `core/gold-standard-testbed/insight_vulnerable.cs` | HIT | Semgrep + marker |
| CSH-048 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-049 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-050 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-051 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-052 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-053 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-054 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-055 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-056 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-057 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-058 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CSH-059 | — | MISS | — |
| CSH-060 | — | MISS | — |
| CSH-061 | — | MISS | — |
| CSH-062 | — | MISS | — |
| CSH-063 | — | MISS | — |
| CSH-064 | — | MISS | — |
| CSH-065 | — | MISS | — |
| CSH-066 | — | MISS | — |
| CSH-067 | — | MISS | — |
| CSH-068 | — | MISS | — |
| CSH-069 | — | MISS | — |
| CSH-070 | — | MISS | — |
| CSH-071 | — | MISS | — |
| CSH-072 | — | MISS | — |
| CSH-073 | — | MISS | — |
| CSH-074 | — | MISS | — |
| CSH-075 | — | MISS | — |
| CSH-076 | — | MISS | — |
| CSH-077 | — | MISS | — |
| CSH-078 | — | MISS | — |
| CSH-079 | — | MISS | — |
| CSH-080 | — | MISS | — |
| CSH-081 | — | MISS | — |
| CSH-082 | — | MISS | — |
| CSH-083 | — | MISS | — |
| CSH-084 | — | MISS | — |
| CSH-085 | — | MISS | — |
| CSH-086 | — | MISS | — |
| CSH-087 | — | MISS | — |
| CWE-1025-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-1104 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-114-CSH-DLL-SEARCH-ORDER | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-114-CSH-PROCESS-START-RELATIVE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-116-JS-PARTIAL-ESCAPE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-116-LLM-HTML-UNTRUSTED | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-116-PY-PARTIAL-ESCAPE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-116-VITE-PROXY-HEADER-FWD | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-117-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-117-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-117-UNIVERSAL-CRLF | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-123-PY-TEMPFILE-TOCTOU | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-124-JS-ARRAYBUFFER-SLICE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-1268-PY-IPC-CHANNEL | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-1271-PY-SIGNED-ERR | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-1280-PY-MARK-CRITICAL | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-1285-PY-NEGOTIATION | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-1321-CSH-DYNAMIC-EXPANDO | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-1321-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-1321-JS-JSON | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-1321-TS-DEEPMERGE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-1333-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-1336-JS-LODASH-TEMPLATE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-1336-JS-PUG-EJS-RTS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-1336-PY-JINJA2-RTS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-1336-PY-MAKO-RTS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-174-JS-CANONICAL | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-174-PY-CANONICAL | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-20-HPP | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-20-JS-VAL-EXTRA-01 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-20-JS-VAL-EXTRA-02 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-20-ORM-MASS-ASSIGN | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-20-PY-VAL-EXTRA-01 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-20-PY-VAL-EXTRA-02 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-20-PY-VAL-EXTRA-03 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-20-UNIVERSAL-NULLBYTE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-20-UNIVERSAL-TYPE-CONFUSION | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-200-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-200-NEXTJS-CLIENT-ENV | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-200-OPENROUTER-APIKEY-LEAK | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-200-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-22-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-22-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-23-JS-DYNAMIC-REQUIRE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-23-JS-EXPRESS-SENDFILE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-23-PY-TEMPLATE-FILE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-250-ELECTRON-REMOTE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-284-BOTO3-PUBLIC-ACL | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-287-KEYCLOAK-JWT-AUD-ISS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-295-BOTO3-PRESIGNED-TTL | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-295-BOTO3-VERIFY-FALSE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-295-JS-ENV | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-295-JS-REQ | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-295-PLAYWRIGHT-HTTPS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-295-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-295-S3-MINIO-VERIFY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-297-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-312-ENV | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-312-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-312-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-327-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-327-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-328-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-338-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-338-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-346-AXIOS-WITHCREDENTIALS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-359-AXIOS-PARAMS-LEAK | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-362-CSH-STATIC-ASYNC-RACE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-362-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-362-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-377-NSIS-OUTPATH-PERM | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-384-CSH-STATIC-TOKEN-CONTEXT | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-384-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-400-GIGAAM-HTTPX-TIMEOUT | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-400-GIGAAM-UPLOAD-LIMITS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-400-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-400-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-400-PY-RESOURCE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-404-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-427-NSIS-EXEC-RELATIVE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-434-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-451-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-451-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-497-CSH-SENSITIVE-LOG | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-502-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-502-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-502-PY-VAL-EXTRA-01 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-524-AXIOS-CACHE-AUTH | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-532-CSH-OFFICE-PII-LOG | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-532-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-532-PY-DECORATOR | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-583-CSH-METADATA-ACL-TRUST | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-601-CSH-PROCESS-START-URL | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-601-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-601-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-606-CSH-UNTRUSTED-LOOP-BOUND | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-611-JS-LIBXMLJS-NOENT | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-611-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-611-PY-ELEMENTTREE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-611-PY-MINIDOM | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-611-PY-VAL-EXTRA-01 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-613-KEYCLOAK-SESSION-CHECKS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-613-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-614-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-670-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-670-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-74-JS-LDAP | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-74-PY-LDAP | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-749-CSH-COMVISIBLE-DANGEROUS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-749-CSH-SINGLETON-PUBLIC-HOOKS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-755-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-755-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-770-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-770-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-772-JS-BUFFER | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-78-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-78-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-79-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-79-JS-SSR-RAW | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-79-JS-VAL-EXTRA-01 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-79-PY-DJANGO-AUTOESCAPE-OFF | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-79-PY-DJANGO-SAFE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-79-PY-HTMLRESPONSE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-79-REACT-DANGEROUSLYSETHTML | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-798-ALEMBIC-URL | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-798-CSH-CONFIG-SECRETS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-80-UNIVERSAL-NOSNIFF | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-81-CSH-WEBBROWSER-XSS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-85-174-UNIVERSAL-ONCE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-85-JS-SLASH-FILTER | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-862-NEXTJS-SERVER-ACTION | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-89-JS-ORM-QUERYRAW | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-89-JS-ORM-RAW | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-89-PG-COPY-PROGRAM | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-89-PLPGSQL-EXECUTE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-89-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-89-PY-DJA-RAW | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-89-PY-SQLALCHEMY-ASYNC-TEXT | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-89-PY-SQLALCHEMY-ORDERBY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-89-PY-SQLALCHEMY-TEXT | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-89-PY-VAL-EXTRA-01 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-89-SQLMODEL-TEXT-FSTRING | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-91-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-91-PY-IDENTITY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-91-UNIVERSAL-XML-CONCAT | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-912-CSH-ANTI-DEBUG-AUTH | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-915-NODE-ASSIGN-MERGE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-915-SQLMODEL-MASS-ASSIGN | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-918-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-918-JS-PROTO | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-918-NEXTJS-AXIOS-SSRF | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-918-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-918-PY-PROTO | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-918-PY-VAL-EXTRA-01 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-922-FASTAPI-HEADER-LOG | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-94-ELECTRON-WEBPREFS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-94-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-94-NODE-EXEC-CONCAT | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-94-OPENROUTER-PROMPT-CONCAT | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-94-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-94-UNIVERSAL-NO-SANDBOX-TEMPLATE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-942-PLAYWRIGHT-WEBSEC | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-942-S3-PUBLIC-ACL | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-943-JS-MONGO-FILTER | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-943-JS-SEQUELIZE-WHERE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-943-PY-DJANGO-KWARGS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-943-PY-MONGO-DICT | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-943-REDIS-CMD | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-943-REDIS-LUA-EVAL | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-943-REDIS-RQ-IREDIS-CMD | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-943-REDIS-RQ-IREDIS-EVAL | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-98-UNIVERSAL-FILE-INFRA-CONTROL | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| DB-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| DB-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| DB-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| DB-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| DB-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| DB-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| DEX-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| DEX-002 | `core/gold-standard-testbed/dynamic_groovy_eval.java` | HIT | Marker (testbed) |
| DEX-003 | `core/gold-standard-testbed/dynamic_groovy_eval.java` | HIT | Semgrep + marker |
| DEX-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| DEX-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| DEX-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| DEX-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| DEX-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| DEX-009 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| DEX-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| DEX-011 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| DEX-012 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| DEX-013 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| DEX-014 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| DEX-015 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| DJA-001 | `core/gold-standard-testbed/django_vulnerable.py` | HIT | Semgrep + marker |
| DJA-002 | `core/gold-standard-testbed/django_vulnerable.py` | HIT | Semgrep + marker |
| DJA-003 | `core/gold-standard-testbed/django_vulnerable.py` | HIT | Semgrep + marker |
| DJA-004 | `core/gold-standard-testbed/django_vulnerable.py` | HIT | Semgrep + marker |
| DJA-005 | `core/gold-standard-testbed/django_vulnerable.py` | HIT | Semgrep + marker |
| DJA-006 | `core/gold-standard-testbed/django_vulnerable.py` | HIT | Semgrep + marker |
| DJA-007 | `core/gold-standard-testbed/django_vulnerable.py` | HIT | Semgrep + marker |
| DJA-008 | `core/gold-standard-testbed/django_vulnerable.py` | HIT | Semgrep + marker |
| DJA-009 | `core/gold-standard-testbed/django_vulnerable.py` | HIT | Semgrep + marker |
| DJA-010 | `core/gold-standard-testbed/django_vulnerable.py` | HIT | Semgrep + marker |
| DJA-011 | `core/gold-standard-testbed/django_vulnerable.py` | HIT | Semgrep + marker |
| DJA-012 | `core/gold-standard-testbed/django_vulnerable.py` | HIT | Semgrep + marker |
| DJA-013 | `core/gold-standard-testbed/django_vulnerable.py` | HIT | Semgrep + marker |
| DJA-014 | `core/gold-standard-testbed/django_vulnerable.py` | HIT | Semgrep + marker |
| DJA-015 | `core/gold-standard-testbed/django_vulnerable.py` | HIT | Semgrep + marker |
| DJA-016 | `core/gold-standard-testbed/django_vulnerable.py` | HIT | Semgrep + marker |
| DJA-017 | `core/gold-standard-testbed/django_vulnerable.py` | HIT | Semgrep + marker |
| DJA-018 | `core/gold-standard-testbed/django_vulnerable.py` | HIT | Semgrep + marker |
| DNX-101 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-102 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-103 | `core/gold-standard-testbed/dotnet_insecure_deserialization.cs` | HIT | Marker (testbed) |
| DNX-104 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-105 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-106 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-107 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-108 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-109 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-110 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-111 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-112 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-113 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-114 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-115 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-116 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-117 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-118 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-119 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-120 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-121 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-122 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-123 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-124 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-125 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-126 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-127 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-128 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-129 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-130 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-131 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-132 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-133 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-134 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-135 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-136 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-137 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-138 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-139 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-140 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-141 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-142 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-143 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-144 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-145 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-146 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-147 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-148 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-149 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-150 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-151 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-152 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-153 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-154 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-155 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-156 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-157 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-158 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-159 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-160 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-161 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-162 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-163 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-164 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-165 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-166 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-167 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-168 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-169 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-170 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-171 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-172 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-173 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-174 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-175 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-176 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-177 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-178 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-179 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-180 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-181 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-182 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-183 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-184 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-185 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-186 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-187 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-188 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-189 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-190 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-191 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-192 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-193 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-194 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-195 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-196 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-197 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-198 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-199 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-200 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-201 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-202 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-203 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-204 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-205 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-206 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-207 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-208 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-209 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-210 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-211 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-212 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-213 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-214 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-215 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-216 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-217 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-218 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-219 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-220 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-221 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-222 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-223 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-224 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-225 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-226 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-227 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-228 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-229 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-230 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-231 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-232 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-233 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-234 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-235 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-236 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-237 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-238 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-239 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-240 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-241 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-242 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-243 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-244 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-245 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-246 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-247 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-248 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-249 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-250 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-251 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-252 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-253 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-254 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-255 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-256 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-257 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-258 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-259 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-260 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-261 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-262 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-263 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-264 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-265 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-266 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-267 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-268 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-269 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-270 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-271 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-272 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-273 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-274 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-275 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-276 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-277 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-278 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-279 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-280 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-281 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-282 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-283 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-284 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-285 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-286 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-287 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-288 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-289 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-290 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-291 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-292 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-293 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-294 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-295 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-296 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-297 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-298 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-299 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-300 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-301 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-302 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-303 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-304 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-305 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-306 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-307 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-308 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-309 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DNX-310 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| DOCK-010 | `core/gold-standard-testbed/Dockerfile` | HIT | Semgrep + marker |
| DOCK-011 | `core/gold-standard-testbed/Dockerfile` | HIT | Semgrep + marker |
| DOCK-012 | `core/gold-standard-testbed/Dockerfile` | HIT | Marker (testbed) |
| DOCK-013 | `core/gold-standard-testbed/Dockerfile` | HIT | Semgrep + marker |
| DOCK-014 | `core/gold-standard-testbed/Dockerfile` | HIT | Semgrep + marker |
| DOCK-015 | `core/gold-standard-testbed/Dockerfile` | HIT | Semgrep + marker |
| DOCK-016 | `core/gold-standard-testbed/Dockerfile` | HIT | Semgrep + marker |
| DOCK-017 | `core/gold-standard-testbed/Dockerfile` | HIT | Semgrep + marker |
| DOCK-018 | `core/gold-standard-testbed/Dockerfile` | HIT | Marker (testbed) |
| DOCK-019 | `core/gold-standard-testbed/Dockerfile` | HIT | Marker (testbed) |
| DOCK-020 | `core/gold-standard-testbed/Dockerfile` | HIT | Marker (testbed) |
| DOCK-021 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| DOCK-022 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| DOCK-023 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| DOCK-024 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| DOCK-025 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| DSK-100 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| DSK-105 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| DSK-110 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| DVS-001 | `core/gold-standard-testbed/devops_security_vulnerable.Dockerfile` | HIT | Semgrep + marker |
| DVS-002 | `core/gold-standard-testbed/devops_security_vulnerable.Dockerfile` | HIT | Marker (testbed) |
| DVS-003 | `core/gold-standard-testbed/devops_security_vulnerable.Dockerfile` | HIT | Marker (testbed) |
| DVS-004 | `core/gold-standard-testbed/devops_security_vulnerable.Dockerfile` | HIT | Semgrep + marker |
| DVS-005 | `core/gold-standard-testbed/devops_security_vulnerable.Dockerfile` | HIT | Semgrep + marker |
| DVS-006 | `core/gold-standard-testbed/devops_security_vulnerable.Dockerfile` | HIT | Marker (testbed) |
| DVS-007 | `core/gold-standard-testbed/devops_security_vulnerable.Dockerfile` | HIT | Semgrep + marker |
| DVS-008 | `core/gold-standard-testbed/devops_security_vulnerable.Dockerfile` | HIT | Semgrep + marker |
| DVS-009 | `core/gold-standard-testbed/devops_security_vulnerable.Dockerfile` | HIT | Marker (testbed) |
| DVS-015 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| DVS-016 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| DVS-017 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| DVS-018 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| DVS-019 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| DVS-020 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| DVS-021 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| DVS-022 | — | MISS | — |
| DVS-023 | — | MISS | — |
| DVS-024 | — | MISS | — |
| DVS-025 | — | MISS | — |
| DVS-026 | — | MISS | — |
| DVS-027 | — | MISS | — |
| DVS-028 | — | MISS | — |
| ENV-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ENV-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ENV-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ENV-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ENV-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ENV-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ENV-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ENV-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ENV-009 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ENV-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ES-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| ES-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| ES-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| ES-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| EXH-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| EXH-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| EXH-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| EXH-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| EXH-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| EXH-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| EXH-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| EXH-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| EXH-009 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| EXH-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| EXH-011 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| EXH-012 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| EXH-013 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| EXH-014 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| EXH-015 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| EXH-016 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| EXH-017 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| EXP-001 | `core/gold-standard-testbed/actuator_leak_config.yaml` | HIT | Marker (testbed) |
| EXP-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| EXP-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| EXP-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| EXP-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| EXP-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| EXP-007 | `core/gold-standard-testbed/actuator_leak_config.yaml` | HIT | Marker (testbed) |
| EXP-008 | `core/gold-standard-testbed/actuator_leak_config.yaml` | HIT | Marker (testbed) |
| EXP-009 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| EXP-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| FAS-001 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-002 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-003 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-004 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-005 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-006 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-007 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Semgrep + marker |
| FAS-008 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-009 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-010 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-011 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-012 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-013 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-014 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-015 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-016 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-017 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-018 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-019 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-020 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-021 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-022 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-023 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-024 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-025 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-026 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-027 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-028 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| FAS-029 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| FAS-030 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| FAS-031 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| FAS-032 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| FAS-033 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| FAS-034 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| FAS-035 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| FAS-036 | — | MISS | — |
| FAS-037 | — | MISS | — |
| FAS-038 | — | MISS | — |
| FAS-039 | — | MISS | — |
| FAS-040 | — | MISS | — |
| FAS-041 | — | MISS | — |
| FAS-042 | — | MISS | — |
| FAS-043 | — | MISS | — |
| FAS-044 | — | MISS | — |
| FAS-045 | — | MISS | — |
| FAS-046 | — | MISS | — |
| FAS-047 | — | MISS | — |
| FAS-048 | — | MISS | — |
| FAS-049 | — | MISS | — |
| FAS-050 | — | MISS | — |
| FAS-051 | — | MISS | — |
| FAS-052 | — | MISS | — |
| FAS-053 | — | MISS | — |
| FAS-054 | — | MISS | — |
| FAS-055 | — | MISS | — |
| FAS-056 | — | MISS | — |
| FAS-057 | — | MISS | — |
| FAS-058 | — | MISS | — |
| FAS-059 | — | MISS | — |
| FAS-060 | — | MISS | — |
| FAS-061 | — | MISS | — |
| FAS-062 | — | MISS | — |
| FAS-063 | — | MISS | — |
| FAS-064 | — | MISS | — |
| FAS-065 | — | MISS | — |
| FAS-066 | — | MISS | — |
| FAS-067 | — | MISS | — |
| FAS-068 | — | MISS | — |
| FAS-069 | — | MISS | — |
| FAS-070 | — | MISS | — |
| FAS-071 | — | MISS | — |
| FAS-072 | — | MISS | — |
| FAS-073 | — | MISS | — |
| FAS-074 | — | MISS | — |
| FAS-075 | — | MISS | — |
| FAS-076 | — | MISS | — |
| FAS-077 | — | MISS | — |
| FAS-078 | — | MISS | — |
| FAS-079 | — | MISS | — |
| FAS-080 | — | MISS | — |
| FAS-081 | — | MISS | — |
| FAS-082 | — | MISS | — |
| FAS-083 | — | MISS | — |
| FAS-084 | — | MISS | — |
| FAS-085 | — | MISS | — |
| FAS-086 | — | MISS | — |
| FAS-087 | — | MISS | — |
| FAS-088 | — | MISS | — |
| FAS-089 | — | MISS | — |
| FAS-090 | — | MISS | — |
| FAS-091 | — | MISS | — |
| FAS-092 | — | MISS | — |
| FAS-093 | — | MISS | — |
| FAS-094 | — | MISS | — |
| FAS-095 | — | MISS | — |
| FAS-096 | — | MISS | — |
| FAS-097 | — | MISS | — |
| FAS-098 | — | MISS | — |
| FAS-099 | — | MISS | — |
| FAS-100 | — | MISS | — |
| FAS-101 | — | MISS | — |
| FAS-102 | — | MISS | — |
| FAS-103 | — | MISS | — |
| FAS-104 | — | MISS | — |
| FAS-105 | — | MISS | — |
| FAS-106 | — | MISS | — |
| FAS-107 | — | MISS | — |
| FAS-108 | — | MISS | — |
| FAS-109 | — | MISS | — |
| FAS-110 | — | MISS | — |
| FAS-111 | — | MISS | — |
| FAS-112 | — | MISS | — |
| FAS-113 | — | MISS | — |
| FAS-114 | — | MISS | — |
| FAS-115 | — | MISS | — |
| FAS-116 | — | MISS | — |
| FAS-117 | — | MISS | — |
| FAS-118 | — | MISS | — |
| FAS-119 | — | MISS | — |
| FAS-120 | — | MISS | — |
| FAS-121 | — | MISS | — |
| FAS-122 | — | MISS | — |
| FAS-123 | — | MISS | — |
| FAS-124 | — | MISS | — |
| FAS-125 | — | MISS | — |
| FAS-126 | — | MISS | — |
| FAS-127 | — | MISS | — |
| FAS-128 | — | MISS | — |
| FAS-129 | — | MISS | — |
| FAS-130 | — | MISS | — |
| FAS-131 | — | MISS | — |
| FAS-132 | — | MISS | — |
| FAS-133 | — | MISS | — |
| FAS-134 | — | MISS | — |
| FAS-135 | — | MISS | — |
| FAS-136 | — | MISS | — |
| FAS-137 | — | MISS | — |
| FAS-138 | — | MISS | — |
| FAS-139 | — | MISS | — |
| FAS-140 | — | MISS | — |
| FAS-141 | — | MISS | — |
| FAS-143 | — | MISS | — |
| FAS-144 | — | MISS | — |
| FAS-145 | — | MISS | — |
| FAS-146 | — | MISS | — |
| FAS-147 | — | MISS | — |
| FAS-148 | — | MISS | — |
| FAS-149 | — | MISS | — |
| FAS-150 | — | MISS | — |
| FAS-151 | — | MISS | — |
| FAS-152 | — | MISS | — |
| FAS-153 | — | MISS | — |
| FAS-154 | — | MISS | — |
| FAS-155 | — | MISS | — |
| FAS-156 | — | MISS | — |
| FAS-157 | — | MISS | — |
| FAS-158 | — | MISS | — |
| FAS-159 | — | MISS | — |
| FAS-160 | — | MISS | — |
| FAS-161 | — | MISS | — |
| FAS-162 | — | MISS | — |
| FAS-163 | — | MISS | — |
| FAS-164 | — | MISS | — |
| FAS-165 | — | MISS | — |
| FAS-166 | — | MISS | — |
| FAS-167 | — | MISS | — |
| FAS-168 | — | MISS | — |
| FAS-169 | — | MISS | — |
| FAS-170 | — | MISS | — |
| FAS-171 | — | MISS | — |
| FAS-172 | — | MISS | — |
| FAS-173 | — | MISS | — |
| FAS-174 | — | MISS | — |
| FAS-175 | — | MISS | — |
| FAS-176 | — | MISS | — |
| FAS-177 | — | MISS | — |
| FAS-178 | — | MISS | — |
| FAS-179 | — | MISS | — |
| FAS-180 | — | MISS | — |
| FAS-181 | — | MISS | — |
| FAS-182 | — | MISS | — |
| FAS-183 | — | MISS | — |
| FAS-184 | — | MISS | — |
| FAS-185 | — | MISS | — |
| FAS-186 | — | MISS | — |
| FAS-187 | — | MISS | — |
| FAS-188 | — | MISS | — |
| FAS-189 | — | MISS | — |
| FAS-190 | — | MISS | — |
| FAS-191 | — | MISS | — |
| FAS-192 | — | MISS | — |
| FAS-193 | — | MISS | — |
| FAS-194 | — | MISS | — |
| FAS-195 | — | MISS | — |
| FAS-196 | — | MISS | — |
| FAS-197 | — | MISS | — |
| FAS-198 | — | MISS | — |
| FAS-199 | — | MISS | — |
| FAS-200 | — | MISS | — |
| FAS-201 | — | MISS | — |
| FAS-202 | — | MISS | — |
| FAS-203 | — | MISS | — |
| FAS-204 | — | MISS | — |
| FAS-205 | — | MISS | — |
| FAS-206 | — | MISS | — |
| FAS-207 | — | MISS | — |
| FAS-208 | — | MISS | — |
| FAS-209 | — | MISS | — |
| FAS-210 | — | MISS | — |
| FAS-211 | — | MISS | — |
| FAS-212 | — | MISS | — |
| FAS-213 | — | MISS | — |
| FAS-214 | — | MISS | — |
| FAS-215 | — | MISS | — |
| FAS-216 | — | MISS | — |
| FAS-217 | — | MISS | — |
| FAS-218 | — | MISS | — |
| FAS-219 | — | MISS | — |
| FAS-220 | — | MISS | — |
| FAS-221 | — | MISS | — |
| FAS-222 | — | MISS | — |
| FAS-223 | — | MISS | — |
| FAS-224 | — | MISS | — |
| FAS-225 | — | MISS | — |
| FAS-226 | — | MISS | — |
| FAS-227 | — | MISS | — |
| FAS-228 | — | MISS | — |
| FAS-229 | — | MISS | — |
| FAS-230 | — | MISS | — |
| FAS-231 | — | MISS | — |
| FAS-232 | — | MISS | — |
| FAS-233 | — | MISS | — |
| FAS-234 | — | MISS | — |
| FAS-235 | — | MISS | — |
| FAS-236 | — | MISS | — |
| FAS-237 | — | MISS | — |
| FAS-238 | — | MISS | — |
| FAS-239 | — | MISS | — |
| FAS-240 | — | MISS | — |
| FAS-241 | — | MISS | — |
| FAS-242 | — | MISS | — |
| FAS-243 | — | MISS | — |
| FAS-244 | — | MISS | — |
| FAS-245 | — | MISS | — |
| FAS-246 | — | MISS | — |
| FAS-247 | — | MISS | — |
| FAS-248 | — | MISS | — |
| FR-001 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Semgrep + marker |
| FR-002 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-003 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-004 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-005 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-006 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-007 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-008 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-009 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-010 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-011 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-012 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-013 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-014 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-015 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-016 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-017 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-018 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-019 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-020 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Semgrep + marker |
| FR-021 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-022 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-023 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-024 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-025 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-026 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-027 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-028 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-029 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-030 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-031 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-032 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-033 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-034 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-035 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-036 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-037 | `core/gold-standard-testbed/typescript/client_redirect_vulnerable.tsx` | HIT | Marker (testbed) |
| FR-038 | `core/gold-standard-testbed/typescript/client_redirect_vulnerable.tsx` | HIT | Marker (testbed) |
| FR-039 | `core/gold-standard-testbed/typescript/client_redirect_vulnerable.tsx` | HIT | Marker (testbed) |
| FR-040 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-041 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-042 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-043 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-044 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-045 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-046 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-047 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-048 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-049 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-050 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-051 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-052 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-053 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-054 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-055 | `core/gold-standard-testbed/typescript/api_client_csrf_vulnerable.ts` | HIT | Marker (testbed) |
| FR-056 | `core/gold-standard-testbed/typescript/api_client_csrf_vulnerable.ts` | HIT | Marker (testbed) |
| FR-057 | `core/gold-standard-testbed/typescript/api_client_csrf_vulnerable.ts` | HIT | Semgrep + marker |
| FR-058 | `core/gold-standard-testbed/typescript/api_client_csrf_vulnerable.ts` | HIT | Marker (testbed) |
| FR-059 | `core/gold-standard-testbed/typescript/api_client_csrf_vulnerable.ts` | HIT | Marker (testbed) |
| FR-060 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-061 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-062 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-063 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-064 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-065 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Semgrep + marker |
| FR-066 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-067 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-068 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-069 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-070 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-071 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-072 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-073 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-074 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-075 | `core/gold-standard-testbed/typescript/dynamic_api_proxy_vulnerable.ts` | HIT | Marker (testbed) |
| FR-076 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-077 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-078 | `core/gold-standard-testbed/typescript/dynamic_api_proxy_vulnerable.ts` | HIT | Marker (testbed) |
| FR-079 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-080 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-081 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-082 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-083 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-084 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-085 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Semgrep + marker |
| FR-086 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-087 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-088 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-089 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-090 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-091 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-092 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-093 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-094 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-095 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-096 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-097 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-098 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-099 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-100 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-101 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-102 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-103 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-104 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-105 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-106 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-107 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-108 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-109 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-110 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-111 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-112 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-113 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-114 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-115 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-116 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-117 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-118 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-119 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-120 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-121 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Semgrep + marker |
| FR-122 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Semgrep + marker |
| FR-123 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Semgrep + marker |
| FR-124 | `core/gold-standard-testbed/typescript/dynamic_api_proxy_vulnerable.ts` | HIT | Marker (testbed) |
| FR-125 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-126 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-127 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-128 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-129 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-130 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-131 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-132 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-133 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-134 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-135 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-136 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Semgrep + marker |
| FR-137 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-138 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-139 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-140 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-141 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-142 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-143 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-144 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-145 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-146 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-147 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-148 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-149 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-150 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-151 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-152 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-153 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-154 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-155 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-156 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-157 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-158 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-159 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-160 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-161 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-162 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-163 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-164 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-165 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-166 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-167 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-168 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-169 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-170 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-171 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-172 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-173 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-174 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-175 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-176 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-177 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-178 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-179 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-180 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-181 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-182 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-183 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-184 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-185 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Semgrep + marker |
| FR-186 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-187 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-188 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-189 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-190 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-191 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-192 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-193 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-194 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-195 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-196 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-197 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-198 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-199 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-200 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-201 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-202 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-203 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-204 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-205 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-206 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-207 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-208 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-209 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-210 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-211 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-212 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-213 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-214 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-215 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-216 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-217 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-218 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-219 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-220 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-221 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-222 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-223 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FR-224 | `core/gold-standard-testbed/typescript/frontend_react_marker.ts` | HIT | Marker (testbed) |
| FTS-001 | `core/gold-standard-testbed/frontend_vulnerable.tsx` | HIT | Marker (testbed) |
| FTS-002 | `core/gold-standard-testbed/frontend_vulnerable.tsx` | HIT | Semgrep + marker |
| FTS-003 | `core/gold-standard-testbed/frontend_vulnerable.tsx` | HIT | Semgrep + marker |
| FTS-004 | `core/gold-standard-testbed/frontend_vulnerable.tsx` | HIT | Marker (testbed) |
| FTS-005 | `core/gold-standard-testbed/frontend_vulnerable.tsx` | HIT | Marker (testbed) |
| FTS-006 | `core/gold-standard-testbed/frontend_vulnerable.tsx` | HIT | Marker (testbed) |
| FTS-007 | `core/gold-standard-testbed/frontend_vulnerable.tsx` | HIT | Marker (testbed) |
| FTS-008 | `core/gold-standard-testbed/frontend_vulnerable.tsx` | HIT | Marker (testbed) |
| FTS-009 | `core/gold-standard-testbed/frontend_vulnerable.tsx` | HIT | Semgrep + marker |
| FTS-010 | `core/gold-standard-testbed/frontend_vulnerable.tsx` | HIT | Marker (testbed) |
| FTS-011 | `core/gold-standard-testbed/frontend_vulnerable.tsx` | HIT | Marker (testbed) |
| FTS-012 | `core/gold-standard-testbed/frontend_vulnerable.tsx` | HIT | Marker (testbed) |
| FTS-013 | `core/gold-standard-testbed/frontend_vulnerable.tsx` | HIT | Marker (testbed) |
| FTS-014 | `core/gold-standard-testbed/frontend_vulnerable.tsx` | HIT | Marker (testbed) |
| FTS-015 | `core/gold-standard-testbed/frontend_vulnerable.tsx` | HIT | Marker (testbed) |
| FTS-016 | `core/gold-standard-testbed/frontend_vulnerable.tsx` | HIT | Marker (testbed) |
| FTS-017 | `core/gold-standard-testbed/frontend_vulnerable.tsx` | HIT | Marker (testbed) |
| FTS-018 | `core/gold-standard-testbed/frontend_vulnerable.tsx` | HIT | Marker (testbed) |
| FTS-019 | `core/gold-standard-testbed/frontend_vulnerable.tsx` | HIT | Semgrep + marker |
| FTS-020 | `core/gold-standard-testbed/frontend_vulnerable.tsx` | HIT | Marker (testbed) |
| GO-001 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| GO-002 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| GO-003 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| GO-004 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| GO-005 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| GO-006 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| GO-007 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| GO-008 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| GO-009 | `core/gold-standard-testbed/multi_lang_vulnerable/go_vulnerable.go` | HIT | Semgrep + marker |
| GO-010 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| GO-011 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| GO-012 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| GO-013 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| GO-014 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| GO-015 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| GO-016 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| GO-017 | `core/gold-standard-testbed/multi_lang_vulnerable/go_vulnerable.go` | HIT | Semgrep + marker |
| GO-018 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| GO-019 | `core/gold-standard-testbed/multi_lang_vulnerable/go_vulnerable.go` | HIT | Semgrep + marker |
| GO-020 | `core/gold-standard-testbed/multi_lang_vulnerable/go_vulnerable.go` | HIT | Semgrep + marker |
| GO-021 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| GO-022 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| GO-023 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| GO-024 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| GO-025 | `core/gold-standard-testbed/multi_lang_vulnerable/go_vulnerable.go` | HIT | Semgrep + marker |
| GO-026 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| GO-027 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| GO-028 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| GO-029 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| GO-030 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| GO-031 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| GO-032 | `core/gold-standard-testbed/multi_lang_vulnerable/go_vulnerable.go` | HIT | Semgrep + marker |
| GO-033 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| GO-034 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| GO-035 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| GO-036 | `core/gold-standard-testbed/multi_lang_vulnerable/go_vulnerable.go` | HIT | Semgrep + marker |
| GO-037 | `core/gold-standard-testbed/multi_lang_vulnerable/go_vulnerable.go` | HIT | Semgrep + marker |
| GO-038 | `core/gold-standard-testbed/multi_lang_vulnerable/go_vulnerable.go` | HIT | Semgrep + marker |
| GO-039 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| GO-040 | `core/gold-standard-testbed/multi_lang_vulnerable/go_vulnerable.go` | HIT | Semgrep + marker |
| GO-041 | `core/gold-standard-testbed/multi_lang_vulnerable/go_vulnerable.go` | HIT | Marker (testbed) |
| GO-042 | `core/gold-standard-testbed/multi_lang_vulnerable/go_vulnerable.go` | HIT | Marker (testbed) |
| GO-043 | `core/gold-standard-testbed/multi_lang_vulnerable/go_vulnerable.go` | HIT | Marker (testbed) |
| GO-044 | `core/gold-standard-testbed/multi_lang_vulnerable/go_vulnerable.go` | HIT | Marker (testbed) |
| GO-045 | `core/gold-standard-testbed/multi_lang_vulnerable/go_vulnerable.go` | HIT | Marker (testbed) |
| GO-046 | `core/gold-standard-testbed/grpc_stream_deadlock_vulnerable.go` | HIT | Marker (testbed) |
| GO-047 | `core/gold-standard-testbed/grpc_auth_bypass.go` | HIT | Marker (testbed) |
| GO-048 | `core/gold-standard-testbed/multi_lang_vulnerable/go_vulnerable.go` | HIT | Semgrep + marker |
| GO-049 | `core/gold-standard-testbed/grpc_auth_bypass.go` | HIT | Marker (testbed) |
| GO-050 | `core/gold-standard-testbed/grpc_auth_bypass.go` | HIT | Marker (testbed) |
| GO-051 | `core/gold-standard-testbed/multi_lang_vulnerable/go_vulnerable.go` | HIT | Marker (testbed) |
| GO-052 | `core/gold-standard-testbed/multi_lang_vulnerable/go_vulnerable.go` | HIT | Marker (testbed) |
| GO-053 | `core/gold-standard-testbed/multi_lang_vulnerable/go_vulnerable.go` | HIT | Marker (testbed) |
| GO-054 | `core/gold-standard-testbed/multi_lang_vulnerable/go_vulnerable.go` | HIT | Marker (testbed) |
| GO-055 | `core/gold-standard-testbed/grpc_stream_deadlock_vulnerable.go` | HIT | Marker (testbed) |
| GO-056 | `core/gold-standard-testbed/multi_lang_vulnerable/go_vulnerable.go` | HIT | Marker (testbed) |
| GO-057 | `core/gold-standard-testbed/multi_lang_vulnerable/go_vulnerable.go` | HIT | Marker (testbed) |
| GO-058 | `core/gold-standard-testbed/multi_lang_vulnerable/go_vulnerable.go` | HIT | Marker (testbed) |
| GO-059 | `core/gold-standard-testbed/grpc_stream_deadlock_vulnerable.go` | HIT | Marker (testbed) |
| GO-060 | `core/gold-standard-testbed/grpc_auth_bypass.go` | HIT | Marker (testbed) |
| GO-061 | — | MISS | — |
| GO-062 | — | MISS | — |
| GO-063 | — | MISS | — |
| GO-064 | — | MISS | — |
| GO-065 | — | MISS | — |
| GO-066 | — | MISS | — |
| GO-067 | — | MISS | — |
| GO-068 | — | MISS | — |
| GO-069 | — | MISS | — |
| GO-070 | — | MISS | — |
| GO-071 | — | MISS | — |
| GO-072 | — | MISS | — |
| GO-073 | — | MISS | — |
| GO-074 | — | MISS | — |
| GO-075 | — | MISS | — |
| GO-076 | — | MISS | — |
| GO-077 | — | MISS | — |
| GO-078 | — | MISS | — |
| GO-079 | — | MISS | — |
| GO-080 | — | MISS | — |
| GO-081 | — | MISS | — |
| GO-082 | — | MISS | — |
| GO-083 | — | MISS | — |
| GO-084 | — | MISS | — |
| GO-085 | — | MISS | — |
| GO-086 | — | MISS | — |
| GO-087 | — | MISS | — |
| GO-088 | — | MISS | — |
| GO-089 | — | MISS | — |
| GO-090 | — | MISS | — |
| GO-091 | — | MISS | — |
| GO-092 | — | MISS | — |
| GO-093 | — | MISS | — |
| GO-094 | — | MISS | — |
| GO-095 | — | MISS | — |
| GO-096 | — | MISS | — |
| GO-097 | — | MISS | — |
| GO-098 | — | MISS | — |
| GO-099 | — | MISS | — |
| GO-100 | — | MISS | — |
| GO-101 | — | MISS | — |
| GO-102 | — | MISS | — |
| GO-103 | — | MISS | — |
| GO-104 | — | MISS | — |
| GO-105 | — | MISS | — |
| GO-106 | — | MISS | — |
| GO-107 | — | MISS | — |
| GO-108 | — | MISS | — |
| GO-109 | — | MISS | — |
| GO-110 | — | MISS | — |
| GO-111 | — | MISS | — |
| GO-112 | — | MISS | — |
| GO-113 | — | MISS | — |
| GO-114 | — | MISS | — |
| GO-115 | — | MISS | — |
| GO-116 | — | MISS | — |
| GO-117 | — | MISS | — |
| GO-118 | — | MISS | — |
| GO-119 | — | MISS | — |
| GOX-101 | `core/gold-standard-testbed/go_mutex_race.go` | HIT | Marker (testbed) |
| GOX-102 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-103 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-104 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-105 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-106 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-107 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-108 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-109 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-110 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-111 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-112 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-113 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-114 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-115 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-116 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-117 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-118 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-119 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-120 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-121 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-122 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-123 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-124 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-125 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-126 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-127 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-128 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-129 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-130 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-131 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-132 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-133 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-134 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-135 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-136 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-137 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-138 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-139 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-140 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-141 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-142 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-143 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-144 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-145 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-146 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-147 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-148 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-149 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-150 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-151 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-152 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-153 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-154 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-155 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-156 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-157 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-158 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-159 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-160 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-161 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-162 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-163 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-164 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-165 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-166 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-167 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-168 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-169 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-170 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-171 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-172 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-173 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-174 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-175 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-176 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-177 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-178 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-179 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-180 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-181 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-182 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-183 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-184 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-185 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-186 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-187 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-188 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-189 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-190 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-191 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-192 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-193 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-194 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-195 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-196 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-197 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-198 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-199 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-200 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-201 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-202 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-203 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-204 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-205 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-206 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-207 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-208 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-209 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-210 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-211 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-212 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-213 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-214 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-215 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-216 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-217 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-218 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-219 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-220 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-221 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-222 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-223 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-224 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-225 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-226 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-227 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-228 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-229 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-230 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-231 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-232 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-233 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-234 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-235 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-236 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-237 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-238 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-239 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-240 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-241 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-242 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-243 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-244 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-245 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-246 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-247 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-248 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-249 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-250 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-251 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-252 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-253 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-254 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-255 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-256 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-257 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-258 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-259 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-260 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-261 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-262 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-263 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-264 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-265 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-266 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-267 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-268 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-269 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-270 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-271 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-272 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-273 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-274 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-275 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-276 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-277 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-278 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-279 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-280 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-281 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-282 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-283 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-284 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-285 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-286 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-287 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-288 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-289 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-290 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-291 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-292 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-293 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-294 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-295 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-296 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-297 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-298 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-299 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-300 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-301 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-302 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-303 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-304 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-305 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-306 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-307 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-308 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-309 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| GOX-310 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| HFT-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-009 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-011 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-012 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-013 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-014 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-015 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-016 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-017 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-018 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-019 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-020 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-021 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-022 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-023 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-024 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-025 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-026 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-027 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-028 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-029 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-030 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-031 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-032 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-033 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-034 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-035 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| HFT-5163 | — | MISS | — |
| HFT-5164 | — | MISS | — |
| HFT-5165 | — | MISS | — |
| HFT-5166 | — | MISS | — |
| HFT-5167 | — | MISS | — |
| HFT-5168 | — | MISS | — |
| HFT-5169 | — | MISS | — |
| HFT-5170 | — | MISS | — |
| HFT-5171 | — | MISS | — |
| HFT-5172 | — | MISS | — |
| HFT-5173 | — | MISS | — |
| HFT-5174 | — | MISS | — |
| HFT-5175 | — | MISS | — |
| HFT-5176 | — | MISS | — |
| HFT-5177 | — | MISS | — |
| HFT-5178 | — | MISS | — |
| HFT-5179 | — | MISS | — |
| HFT-5180 | — | MISS | — |
| HFT-5181 | — | MISS | — |
| HFT-5182 | — | MISS | — |
| HFT-5183 | — | MISS | — |
| HFT-5184 | — | MISS | — |
| HFT-5185 | — | MISS | — |
| HFT-5186 | — | MISS | — |
| HFT-5187 | — | MISS | — |
| HFT-5188 | — | MISS | — |
| HFT-5189 | — | MISS | — |
| HFT-5190 | — | MISS | — |
| HFT-5191 | — | MISS | — |
| HFT-5192 | — | MISS | — |
| HFT-5193 | — | MISS | — |
| HFT-5194 | — | MISS | — |
| HFT-5195 | — | MISS | — |
| HFT-5196 | — | MISS | — |
| HFT-5197 | — | MISS | — |
| HFT-8297 | — | MISS | — |
| HFT-8298 | — | MISS | — |
| HFT-8299 | — | MISS | — |
| HFT-8300 | — | MISS | — |
| HFT-8301 | — | MISS | — |
| HFT-8302 | — | MISS | — |
| HFT-8303 | — | MISS | — |
| HFT-8304 | — | MISS | — |
| HFT-8305 | — | MISS | — |
| HFT-8306 | — | MISS | — |
| HFT-8307 | — | MISS | — |
| HFT-8308 | — | MISS | — |
| HFT-8309 | — | MISS | — |
| HFT-8310 | — | MISS | — |
| HFT-8311 | — | MISS | — |
| HFT-8312 | — | MISS | — |
| HFT-8313 | — | MISS | — |
| HFT-8314 | — | MISS | — |
| HFT-8315 | — | MISS | — |
| HFT-8316 | — | MISS | — |
| HFT-8317 | — | MISS | — |
| HFT-8318 | — | MISS | — |
| HFT-8319 | — | MISS | — |
| HFT-8320 | — | MISS | — |
| HFT-8321 | — | MISS | — |
| HFT-8322 | — | MISS | — |
| HFT-8323 | — | MISS | — |
| HFT-8324 | — | MISS | — |
| HFT-8325 | — | MISS | — |
| HFT-8326 | — | MISS | — |
| HFT-8327 | — | MISS | — |
| HFT-8328 | — | MISS | — |
| HFT-8329 | — | MISS | — |
| HFT-8330 | — | MISS | — |
| HFT-8331 | — | MISS | — |
| HFT-8332 | — | MISS | — |
| HFT-8333 | — | MISS | — |
| HFT-8334 | — | MISS | — |
| HFT-8335 | — | MISS | — |
| HFT-8336 | — | MISS | — |
| HFT-8337 | — | MISS | — |
| HFT-8338 | — | MISS | — |
| HFT-8339 | — | MISS | — |
| HFT-8340 | — | MISS | — |
| HFT-8341 | — | MISS | — |
| HFT-8342 | — | MISS | — |
| HFT-8343 | — | MISS | — |
| HFT-8344 | — | MISS | — |
| HFT-8345 | — | MISS | — |
| HFT-8346 | — | MISS | — |
| HFT-8347 | — | MISS | — |
| HFT-8348 | — | MISS | — |
| HFT-8349 | — | MISS | — |
| HFT-8350 | — | MISS | — |
| HFT-8351 | — | MISS | — |
| HFT-8352 | — | MISS | — |
| HFT-8353 | — | MISS | — |
| HFT-8354 | — | MISS | — |
| HFT-8355 | — | MISS | — |
| HFT-8356 | — | MISS | — |
| HFT-8357 | — | MISS | — |
| HFT-8358 | — | MISS | — |
| HFT-8359 | — | MISS | — |
| HFT-8360 | — | MISS | — |
| HFT-8361 | — | MISS | — |
| HFT-8362 | — | MISS | — |
| HFT-8363 | — | MISS | — |
| HFT-8364 | — | MISS | — |
| HFT-8365 | — | MISS | — |
| HFT-8366 | — | MISS | — |
| HFT-8367 | — | MISS | — |
| HFT-8368 | — | MISS | — |
| HFT-8369 | — | MISS | — |
| HFT-8370 | — | MISS | — |
| HFT-8371 | — | MISS | — |
| HFT-8372 | — | MISS | — |
| HFT-8373 | — | MISS | — |
| HFT-8374 | — | MISS | — |
| HFT-8375 | — | MISS | — |
| HFT-8376 | — | MISS | — |
| HFT-8377 | — | MISS | — |
| HFT-8378 | — | MISS | — |
| HFT-8379 | — | MISS | — |
| HFT-8380 | — | MISS | — |
| HFT-8381 | — | MISS | — |
| HFT-8382 | — | MISS | — |
| HFT-8383 | — | MISS | — |
| HFT-8384 | — | MISS | — |
| HFT-8385 | — | MISS | — |
| HFT-8386 | — | MISS | — |
| HFT-8387 | — | MISS | — |
| HFT-8388 | — | MISS | — |
| HFT-8389 | — | MISS | — |
| HFT-8390 | — | MISS | — |
| HFT-8391 | — | MISS | — |
| HFT-8392 | — | MISS | — |
| HFT-8393 | — | MISS | — |
| HFT-8394 | — | MISS | — |
| HFT-8395 | — | MISS | — |
| HFT-8396 | — | MISS | — |
| HFT-8397 | — | MISS | — |
| HFT-8398 | — | MISS | — |
| HFT-8399 | — | MISS | — |
| HFT-8400 | — | MISS | — |
| HFT-8401 | — | MISS | — |
| HFT-8402 | — | MISS | — |
| HFT-8403 | — | MISS | — |
| HFT-8404 | — | MISS | — |
| HFT-8405 | — | MISS | — |
| HFT-8406 | — | MISS | — |
| HFT-8407 | — | MISS | — |
| HFT-8408 | — | MISS | — |
| HFT-8409 | — | MISS | — |
| HFT-8410 | — | MISS | — |
| HFT-8411 | — | MISS | — |
| HFT-8412 | — | MISS | — |
| HFT-8413 | — | MISS | — |
| HFT-8414 | — | MISS | — |
| HFT-8415 | — | MISS | — |
| HFT-8416 | — | MISS | — |
| HFT-8417 | — | MISS | — |
| HFT-8418 | — | MISS | — |
| HFT-8419 | — | MISS | — |
| HFT-8420 | — | MISS | — |
| HFT-8421 | — | MISS | — |
| HFT-8422 | — | MISS | — |
| HFT-8423 | — | MISS | — |
| HFT-8424 | — | MISS | — |
| HFT-8425 | — | MISS | — |
| HFT-8426 | — | MISS | — |
| HFT-8427 | — | MISS | — |
| HFT-8428 | — | MISS | — |
| HFT-8429 | — | MISS | — |
| HFT-8430 | — | MISS | — |
| HFT-8431 | — | MISS | — |
| HFT-8432 | — | MISS | — |
| HFT-8433 | — | MISS | — |
| HFT-8434 | — | MISS | — |
| HFT-8435 | — | MISS | — |
| HFT-8436 | — | MISS | — |
| HFT-8437 | — | MISS | — |
| HFT-8438 | — | MISS | — |
| HFT-8439 | — | MISS | — |
| HFT-8440 | — | MISS | — |
| HFT-8441 | — | MISS | — |
| HFT-8442 | — | MISS | — |
| HFT-8443 | — | MISS | — |
| HFT-8444 | — | MISS | — |
| HFT-8445 | — | MISS | — |
| HFT-8446 | — | MISS | — |
| HFT-8447 | — | MISS | — |
| HFT-8448 | — | MISS | — |
| HFT-8449 | — | MISS | — |
| HFT-8450 | — | MISS | — |
| HFT-8451 | — | MISS | — |
| HFT-8452 | — | MISS | — |
| HFT-8453 | — | MISS | — |
| HFT-8454 | — | MISS | — |
| HFT-8455 | — | MISS | — |
| HFT-8456 | — | MISS | — |
| HFT-8457 | — | MISS | — |
| HFT-8458 | — | MISS | — |
| HFT-8459 | — | MISS | — |
| HFT-8460 | — | MISS | — |
| HFT-8461 | — | MISS | — |
| HFT-8462 | — | MISS | — |
| HFT-8463 | — | MISS | — |
| HFT-8464 | — | MISS | — |
| HFT-8465 | — | MISS | — |
| HFT-8466 | — | MISS | — |
| HFT-8467 | — | MISS | — |
| HFT-8468 | — | MISS | — |
| HFT-8469 | — | MISS | — |
| HFT-8470 | — | MISS | — |
| HFT-8471 | — | MISS | — |
| HFT-8472 | — | MISS | — |
| HFT-8473 | — | MISS | — |
| HFT-8474 | — | MISS | — |
| HFT-8475 | — | MISS | — |
| HFT-8476 | — | MISS | — |
| HFT-8477 | — | MISS | — |
| HFT-8478 | — | MISS | — |
| HFT-8479 | — | MISS | — |
| HFT-8480 | — | MISS | — |
| HFT-8481 | — | MISS | — |
| HFT-8482 | — | MISS | — |
| HFT-8483 | — | MISS | — |
| HFT-8484 | — | MISS | — |
| HFT-8485 | — | MISS | — |
| HFT-8486 | — | MISS | — |
| HFT-8487 | — | MISS | — |
| HFT-8488 | — | MISS | — |
| HFT-8489 | — | MISS | — |
| HFT-8490 | — | MISS | — |
| HFT-8491 | — | MISS | — |
| HFT-8492 | — | MISS | — |
| HFT-8493 | — | MISS | — |
| HFT-8494 | — | MISS | — |
| HFT-8495 | — | MISS | — |
| HFT-8496 | — | MISS | — |
| HFT-8497 | — | MISS | — |
| HFT-8498 | — | MISS | — |
| HFT-8499 | — | MISS | — |
| HFT-8500 | — | MISS | — |
| HFT-8501 | — | MISS | — |
| HFT-8502 | — | MISS | — |
| HFT-8503 | — | MISS | — |
| HFT-8504 | — | MISS | — |
| HFT-8505 | — | MISS | — |
| HFT-8506 | — | MISS | — |
| HFT-8507 | — | MISS | — |
| HFT-8508 | — | MISS | — |
| HFT-8509 | — | MISS | — |
| HFT-8510 | — | MISS | — |
| HFT-8511 | — | MISS | — |
| HFT-8512 | — | MISS | — |
| HFT-8513 | — | MISS | — |
| HFT-8514 | — | MISS | — |
| HFT-8515 | — | MISS | — |
| HFT-8516 | — | MISS | — |
| HFT-8517 | — | MISS | — |
| HFT-8518 | — | MISS | — |
| HFT-8519 | — | MISS | — |
| HFT-8520 | — | MISS | — |
| HFT-8521 | — | MISS | — |
| HFT-8522 | — | MISS | — |
| HFT-8523 | — | MISS | — |
| HFT-8524 | — | MISS | — |
| HFT-8525 | — | MISS | — |
| HFT-8526 | — | MISS | — |
| HFT-8527 | — | MISS | — |
| HFT-8528 | — | MISS | — |
| HFT-8529 | — | MISS | — |
| HFT-8530 | — | MISS | — |
| HFT-8531 | — | MISS | — |
| HFT-8532 | — | MISS | — |
| HFT-8533 | — | MISS | — |
| HFT-8534 | — | MISS | — |
| HFT-8535 | — | MISS | — |
| HFT-8536 | — | MISS | — |
| HFT-8537 | — | MISS | — |
| HFT-8538 | — | MISS | — |
| HFT-8539 | — | MISS | — |
| HFT-8540 | — | MISS | — |
| HFT-8541 | — | MISS | — |
| HFT-8542 | — | MISS | — |
| HFT-8543 | — | MISS | — |
| HFT-8544 | — | MISS | — |
| HFT-8545 | — | MISS | — |
| HFT-8546 | — | MISS | — |
| IAC-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| IAC-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| IAC-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| IAC-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| IAC-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| IAC-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| IAC-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| IAC-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| IAC-009 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| IAC-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| IAC-011 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| IAC-012 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| IAC-013 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| IAC-014 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| IAC-015 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| IAC-016 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| IAC-017 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| IAC-018 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| IAC-019 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| IAC-020 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| IFF-001 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-002 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFF-003 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-004 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-005 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFF-006 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-007 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-008 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFF-009 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-010 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-011 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFF-012 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-013 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-014 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFF-015 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-016 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-017 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFF-018 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-019 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-020 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFF-021 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-022 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-023 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFF-024 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-025 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-026 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFF-027 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-028 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-029 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFF-030 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-031 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-032 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFF-033 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-034 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-035 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFF-036 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-037 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-038 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFF-039 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-040 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-041 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFF-042 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-043 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-044 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFF-045 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-046 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-047 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFF-048 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-049 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFF-050 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFJ-001 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-002 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFJ-003 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-004 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-005 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFJ-006 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-007 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-008 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFJ-009 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-010 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-011 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFJ-012 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-013 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-014 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFJ-015 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-016 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-017 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFJ-018 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-019 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-020 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFJ-021 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-022 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-023 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFJ-024 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-025 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-026 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFJ-027 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-028 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-029 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFJ-030 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-031 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-032 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFJ-033 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-034 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-035 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFJ-036 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-037 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-038 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFJ-039 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-040 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-041 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFJ-042 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-043 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-044 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFJ-045 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-046 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-047 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFJ-048 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-049 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFJ-050 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFN-001 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-002 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFN-003 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-004 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-005 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFN-006 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-007 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-008 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFN-009 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-010 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-011 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFN-012 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-013 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-014 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFN-015 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-016 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-017 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFN-018 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-019 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-020 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFN-021 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-022 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-023 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFN-024 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-025 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-026 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFN-027 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-028 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-029 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFN-030 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-031 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-032 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFN-033 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-034 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-035 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFN-036 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-037 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-038 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFN-039 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-040 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-041 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFN-042 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-043 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-044 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFN-045 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-046 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-047 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| IFN-048 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-049 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| IFN-050 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Semgrep + marker |
| INF-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| INF-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| INF-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| INF-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| INF-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| INF-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| INF-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| INF-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| INF-009 | `core/gold-standard-testbed/deployment-test.yaml` | HIT | Semgrep + marker |
| INF-010 | `core/gold-standard-testbed/infra_vulnerable.yaml` | HIT | Semgrep + marker |
| INF-011 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-012 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-013 | `core/gold-standard-testbed/infra_vulnerable.yaml` | HIT | Semgrep + marker |
| INF-014 | `core/gold-standard-testbed/infra_vulnerable.yaml` | HIT | Semgrep + marker |
| INF-015 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-016 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-017 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-018 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-019 | — | HIT | Semgrep |
| INF-020 | — | HIT | Semgrep |
| INF-021 | — | MISS | — |
| INF-022 | — | HIT | Semgrep |
| INF-023 | — | MISS | — |
| INF-024 | — | HIT | Semgrep |
| INF-025 | — | HIT | Semgrep |
| INF-026 | — | HIT | Semgrep |
| INF-027 | — | HIT | Semgrep |
| INF-028 | — | HIT | Semgrep |
| INF-029 | — | HIT | Semgrep |
| INF-030 | — | HIT | Semgrep |
| INF-031 | — | HIT | Semgrep |
| INF-032 | — | MISS | — |
| INF-033 | — | MISS | — |
| INF-034 | — | HIT | Semgrep |
| INF-035 | — | HIT | Semgrep |
| INF-036 | — | HIT | Semgrep |
| INF-037 | — | HIT | Semgrep |
| INF-038 | — | HIT | Semgrep |
| INF-039 | — | MISS | — |
| INF-040 | — | HIT | Semgrep |
| INF-041 | — | HIT | Semgrep |
| INF-042 | — | MISS | — |
| INF-043 | — | HIT | Semgrep |
| INF-044 | — | MISS | — |
| INF-045 | — | HIT | Semgrep |
| INF-046 | — | MISS | — |
| INF-047 | — | HIT | Semgrep |
| INF-048 | — | HIT | Semgrep |
| INF-049 | — | MISS | — |
| INF-050 | — | HIT | Semgrep |
| INF-051 | — | HIT | Semgrep |
| INF-052 | — | MISS | — |
| INF-053 | — | HIT | Semgrep |
| INF-054 | — | HIT | Semgrep |
| INF-055 | — | HIT | Semgrep |
| INF-056 | — | HIT | Semgrep |
| INF-057 | — | HIT | Semgrep |
| INF-058 | — | HIT | Semgrep |
| INF-059 | — | HIT | Semgrep |
| INF-060 | — | HIT | Semgrep |
| INF-061 | — | MISS | — |
| INF-062 | — | HIT | Semgrep |
| INF-063 | — | MISS | — |
| INF-064 | — | HIT | Semgrep |
| INF-065 | — | MISS | — |
| INF-066 | — | MISS | — |
| INF-067 | — | MISS | — |
| INF-068 | — | HIT | Semgrep |
| INF-069 | — | HIT | Semgrep |
| INF-070 | — | HIT | Semgrep |
| INF-071 | — | HIT | Semgrep |
| INF-072 | — | HIT | Semgrep |
| INF-073 | — | HIT | Semgrep |
| INF-074 | — | HIT | Semgrep |
| INF-075 | — | MISS | — |
| INF-076 | — | HIT | Semgrep |
| INF-077 | — | HIT | Semgrep |
| INF-078 | — | HIT | Semgrep |
| INF-079 | — | HIT | Semgrep |
| INF-080 | — | HIT | Semgrep |
| INF-081 | — | HIT | Semgrep |
| INF-082 | — | HIT | Semgrep |
| INF-083 | — | HIT | Semgrep |
| INF-084 | — | MISS | — |
| INF-085 | — | HIT | Semgrep |
| INF-086 | — | HIT | Semgrep |
| INF-087 | — | MISS | — |
| INF-088 | — | HIT | Semgrep |
| INF-089 | — | HIT | Semgrep |
| INF-090 | — | HIT | Semgrep |
| INF-091 | — | MISS | — |
| INF-092 | — | MISS | — |
| INF-093 | — | MISS | — |
| INF-094 | — | MISS | — |
| INF-095 | — | MISS | — |
| INF-096 | — | HIT | Semgrep |
| INF-097 | — | MISS | — |
| INF-098 | — | MISS | — |
| INF-099 | — | HIT | Semgrep |
| INF-1.2.1 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-1.2.33 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-1.2.6 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-2.5.1 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-200 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-201 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-202 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-203 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-204 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-205 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-206 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-207 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-208 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-209 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-210 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-211 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-212 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-213 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-214 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-215 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-216 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-217 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-218 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-219 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-220 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-4.1 | `core/gold-standard-testbed/Dockerfile` | HIT | Marker (testbed) |
| INF-4.4 | `core/gold-standard-testbed/Dockerfile` | HIT | Marker (testbed) |
| INF-5.1.1 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-5.1.2-TLS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-5.10 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-5.2.1 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-5.2.4 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-5.2.5 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-5.25 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-5.3.1 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-5.3.1-NGX | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-5.3.2 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-5.5.1 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-5.6.2 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-001 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Semgrep + marker |
| INS-002 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Semgrep + marker |
| INS-003 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Semgrep + marker |
| INS-004 | `core/gold-standard-testbed/insight_vulnerable.cs` | HIT | Semgrep + marker |
| INS-005 | `core/gold-standard-testbed/insight_vulnerable.cs` | HIT | Semgrep + marker |
| INS-006 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Semgrep + marker |
| INS-007 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-008 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Semgrep + marker |
| INS-009 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-010 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-011 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-012 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-013 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-014 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-015 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-016 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-017 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-018 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-019 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-020 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-021 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-022 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-023 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-024 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-025 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-026 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-027 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-028 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| INS-029 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-030 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-031 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-032 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-033 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| INS-034 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-035 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-036 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-037 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-038 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-039 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-040 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-041 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-042 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-043 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-044 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-045 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-046 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-047 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-048 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-049 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-050 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-051 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-052 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-053 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-054 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-055 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-056 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| INS-057 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-058 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| INS-059 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| INS-060 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| INS-061 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-062 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| INS-063 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| INS-064 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-065 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| INS-066 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| INS-067 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-068 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-069 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INS-070 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| INS-071 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| INS-072 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-073 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-074 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-075 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-076 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-077 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-078 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-079 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-080 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-081 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-082 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-083 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-084 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-085 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-086 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-087 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-088 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-089 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-090 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-091 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-092 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-093 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-094 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-095 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-096 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-097 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-098 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-099 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-100 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-101 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-102 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-103 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-104 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-105 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-106 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-107 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-108 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-109 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-110 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-111 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-112 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-113 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-114 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-115 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-116 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-117 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-118 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-119 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-120 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-121 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-122 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-123 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-124 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-125 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-126 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-127 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-128 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-129 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-130 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-131 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-132 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Semgrep + marker |
| INS-133 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-134 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-135 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-136 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-137 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-138 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-139 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-140 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-141 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-142 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-143 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-144 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-145 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-146 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-147 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-148 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-149 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-150 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-151 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| INS-152 | `core/gold-standard-testbed/insight_vulnerable.ts` | HIT | Marker (testbed) |
| ITS-001 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| ITS-002 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| ITS-003 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| ITS-004 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| ITS-005 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| ITS-006 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| ITS-007 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| ITS-008 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| ITS-009 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| ITS-010 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| ITS-011 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| ITS-012 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| ITS-013 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| ITS-014 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| ITS-015 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| ITS-016 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| ITS-017 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| ITS-018 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| ITS-019 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| ITS-020 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| ITS-021 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| ITS-022 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| ITS-023 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| ITS-024 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| ITS-025 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| ITS-026 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| ITS-027 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| ITS-028 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| ITS-029 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| ITS-030 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| ITS-031 | — | MISS | — |
| ITS-032 | — | MISS | — |
| ITS-033 | — | MISS | — |
| ITS-034 | — | MISS | — |
| ITS-035 | — | MISS | — |
| ITS-036 | — | MISS | — |
| ITS-037 | — | HIT | Semgrep |
| ITS-038 | — | HIT | Semgrep |
| ITS-039 | — | MISS | — |
| ITS-040 | — | MISS | — |
| ITS-041 | — | MISS | — |
| ITS-042 | — | MISS | — |
| ITS-043 | — | MISS | — |
| ITS-044 | — | MISS | — |
| ITS-045 | — | HIT | Semgrep |
| ITS-046 | — | MISS | — |
| ITS-047 | — | MISS | — |
| ITS-048 | — | MISS | — |
| ITS-049 | — | MISS | — |
| ITS-050 | — | MISS | — |
| ITS-051 | — | MISS | — |
| ITS-052 | — | MISS | — |
| ITS-053 | — | MISS | — |
| ITS-054 | — | MISS | — |
| ITS-055 | — | MISS | — |
| ITS-056 | — | HIT | Semgrep |
| ITS-057 | — | HIT | Semgrep |
| ITS-058 | — | MISS | — |
| ITS-059 | — | MISS | — |
| ITS-060 | — | HIT | Semgrep |
| ITS-061 | — | MISS | — |
| ITS-062 | — | MISS | — |
| ITS-063 | — | MISS | — |
| ITS-064 | — | MISS | — |
| ITS-065 | — | MISS | — |
| ITS-066 | — | MISS | — |
| ITS-067 | — | MISS | — |
| ITS-068 | — | HIT | Semgrep |
| ITS-069 | — | MISS | — |
| ITS-070 | — | MISS | — |
| ITS-071 | — | MISS | — |
| ITS-072 | — | MISS | — |
| ITS-073 | — | MISS | — |
| ITS-074 | — | MISS | — |
| ITS-075 | — | MISS | — |
| ITS-076 | — | MISS | — |
| ITS-077 | — | MISS | — |
| ITS-078 | — | MISS | — |
| ITS-079 | — | MISS | — |
| ITS-080 | — | MISS | — |
| ITS-081 | — | MISS | — |
| ITS-082 | — | MISS | — |
| ITS-083 | — | MISS | — |
| ITS-084 | — | MISS | — |
| ITS-085 | — | MISS | — |
| ITS-086 | — | MISS | — |
| ITS-087 | — | HIT | Semgrep |
| ITS-088 | — | MISS | — |
| ITS-089 | — | MISS | — |
| ITS-090 | — | MISS | — |
| ITS-091 | — | MISS | — |
| ITS-092 | — | MISS | — |
| ITS-093 | — | MISS | — |
| ITS-094 | — | MISS | — |
| ITS-095 | — | MISS | — |
| ITS-096 | — | MISS | — |
| ITS-097 | — | MISS | — |
| ITS-098 | — | MISS | — |
| ITS-099 | — | MISS | — |
| ITS-100 | — | MISS | — |
| ITS-1000 | — | MISS | — |
| ITS-1001 | — | MISS | — |
| ITS-1002 | — | MISS | — |
| ITS-1003 | — | MISS | — |
| ITS-1004 | — | MISS | — |
| ITS-1005 | — | MISS | — |
| ITS-1006 | — | MISS | — |
| ITS-1007 | — | MISS | — |
| ITS-1008 | — | MISS | — |
| ITS-1009 | — | MISS | — |
| ITS-101 | — | MISS | — |
| ITS-1010 | — | MISS | — |
| ITS-1011 | — | MISS | — |
| ITS-1012 | — | MISS | — |
| ITS-1013 | — | MISS | — |
| ITS-1014 | — | MISS | — |
| ITS-1015 | — | MISS | — |
| ITS-1016 | — | MISS | — |
| ITS-1017 | — | MISS | — |
| ITS-1018 | — | MISS | — |
| ITS-1019 | — | MISS | — |
| ITS-102 | — | MISS | — |
| ITS-1020 | — | MISS | — |
| ITS-1021 | — | MISS | — |
| ITS-1022 | — | MISS | — |
| ITS-1023 | — | MISS | — |
| ITS-1024 | — | MISS | — |
| ITS-1025 | — | MISS | — |
| ITS-1026 | — | MISS | — |
| ITS-1027 | — | MISS | — |
| ITS-1028 | — | MISS | — |
| ITS-1029 | — | MISS | — |
| ITS-103 | — | MISS | — |
| ITS-1030 | — | MISS | — |
| ITS-1031 | — | MISS | — |
| ITS-1032 | — | MISS | — |
| ITS-1033 | — | MISS | — |
| ITS-1034 | — | MISS | — |
| ITS-1035 | — | MISS | — |
| ITS-1036 | — | MISS | — |
| ITS-1037 | — | MISS | — |
| ITS-1038 | — | MISS | — |
| ITS-1039 | — | MISS | — |
| ITS-104 | — | MISS | — |
| ITS-1040 | — | MISS | — |
| ITS-1041 | — | MISS | — |
| ITS-1042 | — | MISS | — |
| ITS-1043 | — | MISS | — |
| ITS-1044 | — | MISS | — |
| ITS-1045 | — | MISS | — |
| ITS-1046 | — | MISS | — |
| ITS-1047 | — | MISS | — |
| ITS-1048 | — | MISS | — |
| ITS-1049 | — | MISS | — |
| ITS-105 | — | MISS | — |
| ITS-1050 | — | MISS | — |
| ITS-1051 | — | MISS | — |
| ITS-1052 | — | MISS | — |
| ITS-1053 | — | MISS | — |
| ITS-1054 | — | MISS | — |
| ITS-1055 | — | MISS | — |
| ITS-1056 | — | MISS | — |
| ITS-1057 | — | MISS | — |
| ITS-1058 | — | MISS | — |
| ITS-1059 | — | MISS | — |
| ITS-106 | — | MISS | — |
| ITS-1060 | — | MISS | — |
| ITS-1061 | — | MISS | — |
| ITS-1062 | — | MISS | — |
| ITS-1063 | — | MISS | — |
| ITS-1064 | — | MISS | — |
| ITS-1065 | — | MISS | — |
| ITS-1066 | — | MISS | — |
| ITS-1067 | — | MISS | — |
| ITS-1068 | — | MISS | — |
| ITS-1069 | — | MISS | — |
| ITS-107 | — | MISS | — |
| ITS-1070 | — | MISS | — |
| ITS-1071 | — | MISS | — |
| ITS-1072 | — | MISS | — |
| ITS-1073 | — | MISS | — |
| ITS-1074 | — | MISS | — |
| ITS-1075 | — | MISS | — |
| ITS-1076 | — | MISS | — |
| ITS-1077 | — | MISS | — |
| ITS-1078 | — | MISS | — |
| ITS-1079 | — | MISS | — |
| ITS-108 | — | MISS | — |
| ITS-1080 | — | MISS | — |
| ITS-1081 | — | MISS | — |
| ITS-1082 | — | MISS | — |
| ITS-1083 | — | MISS | — |
| ITS-1084 | — | MISS | — |
| ITS-1085 | — | MISS | — |
| ITS-1086 | — | MISS | — |
| ITS-1087 | — | MISS | — |
| ITS-1088 | — | MISS | — |
| ITS-1089 | — | MISS | — |
| ITS-109 | — | MISS | — |
| ITS-1090 | — | MISS | — |
| ITS-1091 | — | MISS | — |
| ITS-1092 | — | MISS | — |
| ITS-1093 | — | MISS | — |
| ITS-1094 | — | MISS | — |
| ITS-1095 | — | MISS | — |
| ITS-1096 | — | MISS | — |
| ITS-1097 | — | MISS | — |
| ITS-1098 | — | MISS | — |
| ITS-1099 | — | MISS | — |
| ITS-110 | — | MISS | — |
| ITS-1100 | — | MISS | — |
| ITS-1101 | — | MISS | — |
| ITS-1102 | — | MISS | — |
| ITS-1103 | — | MISS | — |
| ITS-1104 | — | MISS | — |
| ITS-1105 | — | MISS | — |
| ITS-1106 | — | MISS | — |
| ITS-1107 | — | MISS | — |
| ITS-1108 | — | MISS | — |
| ITS-1109 | — | MISS | — |
| ITS-111 | — | MISS | — |
| ITS-1110 | — | MISS | — |
| ITS-1111 | — | MISS | — |
| ITS-1112 | — | MISS | — |
| ITS-1113 | — | MISS | — |
| ITS-1114 | — | MISS | — |
| ITS-1115 | — | MISS | — |
| ITS-1116 | — | MISS | — |
| ITS-1117 | — | MISS | — |
| ITS-1118 | — | MISS | — |
| ITS-1119 | — | MISS | — |
| ITS-112 | — | MISS | — |
| ITS-1120 | — | MISS | — |
| ITS-1121 | — | MISS | — |
| ITS-1122 | — | MISS | — |
| ITS-1123 | — | MISS | — |
| ITS-1124 | — | MISS | — |
| ITS-1125 | — | MISS | — |
| ITS-1126 | — | MISS | — |
| ITS-1127 | — | MISS | — |
| ITS-1128 | — | MISS | — |
| ITS-1129 | — | MISS | — |
| ITS-113 | — | MISS | — |
| ITS-1130 | — | MISS | — |
| ITS-1131 | — | MISS | — |
| ITS-1132 | — | MISS | — |
| ITS-1133 | — | MISS | — |
| ITS-1134 | — | MISS | — |
| ITS-1135 | — | MISS | — |
| ITS-1136 | — | MISS | — |
| ITS-1137 | — | MISS | — |
| ITS-1138 | — | MISS | — |
| ITS-1139 | — | MISS | — |
| ITS-114 | — | MISS | — |
| ITS-1140 | — | MISS | — |
| ITS-1141 | — | MISS | — |
| ITS-1142 | — | MISS | — |
| ITS-1143 | — | MISS | — |
| ITS-1144 | — | MISS | — |
| ITS-1145 | — | MISS | — |
| ITS-1146 | — | MISS | — |
| ITS-1147 | — | MISS | — |
| ITS-1148 | — | MISS | — |
| ITS-1149 | — | MISS | — |
| ITS-115 | — | MISS | — |
| ITS-1150 | — | MISS | — |
| ITS-1151 | — | MISS | — |
| ITS-1152 | — | MISS | — |
| ITS-1153 | — | MISS | — |
| ITS-1154 | — | MISS | — |
| ITS-1155 | — | MISS | — |
| ITS-1156 | — | MISS | — |
| ITS-1157 | — | MISS | — |
| ITS-1158 | — | MISS | — |
| ITS-1159 | — | MISS | — |
| ITS-116 | — | MISS | — |
| ITS-1160 | — | MISS | — |
| ITS-1161 | — | MISS | — |
| ITS-1162 | — | MISS | — |
| ITS-1163 | — | MISS | — |
| ITS-1164 | — | MISS | — |
| ITS-1165 | — | MISS | — |
| ITS-1166 | — | MISS | — |
| ITS-1167 | — | MISS | — |
| ITS-1168 | — | MISS | — |
| ITS-1169 | — | MISS | — |
| ITS-117 | — | MISS | — |
| ITS-1170 | — | MISS | — |
| ITS-1171 | — | MISS | — |
| ITS-1172 | — | MISS | — |
| ITS-1173 | — | MISS | — |
| ITS-1174 | — | MISS | — |
| ITS-1175 | — | MISS | — |
| ITS-1176 | — | MISS | — |
| ITS-1177 | — | MISS | — |
| ITS-1178 | — | MISS | — |
| ITS-1179 | — | MISS | — |
| ITS-118 | — | MISS | — |
| ITS-1180 | — | MISS | — |
| ITS-1181 | — | MISS | — |
| ITS-1182 | — | MISS | — |
| ITS-1183 | — | MISS | — |
| ITS-1184 | — | MISS | — |
| ITS-1185 | — | MISS | — |
| ITS-1186 | — | MISS | — |
| ITS-1187 | — | MISS | — |
| ITS-1188 | — | MISS | — |
| ITS-1189 | — | MISS | — |
| ITS-119 | — | MISS | — |
| ITS-1190 | — | MISS | — |
| ITS-1191 | — | MISS | — |
| ITS-1192 | — | MISS | — |
| ITS-1193 | — | MISS | — |
| ITS-1194 | — | MISS | — |
| ITS-1195 | — | MISS | — |
| ITS-1196 | — | MISS | — |
| ITS-1197 | — | MISS | — |
| ITS-1198 | — | MISS | — |
| ITS-1199 | — | MISS | — |
| ITS-120 | — | HIT | Semgrep |
| ITS-1200 | — | MISS | — |
| ITS-1201 | — | MISS | — |
| ITS-1202 | — | MISS | — |
| ITS-1203 | — | MISS | — |
| ITS-1204 | — | MISS | — |
| ITS-1205 | — | MISS | — |
| ITS-1206 | — | MISS | — |
| ITS-1207 | — | MISS | — |
| ITS-1208 | — | MISS | — |
| ITS-1209 | — | MISS | — |
| ITS-121 | — | MISS | — |
| ITS-1210 | — | MISS | — |
| ITS-1211 | — | MISS | — |
| ITS-1212 | — | MISS | — |
| ITS-1213 | — | MISS | — |
| ITS-1214 | — | MISS | — |
| ITS-1215 | — | MISS | — |
| ITS-1216 | — | MISS | — |
| ITS-1217 | — | MISS | — |
| ITS-1218 | — | MISS | — |
| ITS-1219 | — | MISS | — |
| ITS-122 | — | MISS | — |
| ITS-1220 | — | MISS | — |
| ITS-1221 | — | MISS | — |
| ITS-1222 | — | MISS | — |
| ITS-1223 | — | MISS | — |
| ITS-1224 | — | MISS | — |
| ITS-1225 | — | MISS | — |
| ITS-1226 | — | MISS | — |
| ITS-1227 | — | MISS | — |
| ITS-1228 | — | MISS | — |
| ITS-1229 | — | MISS | — |
| ITS-123 | — | MISS | — |
| ITS-1230 | — | MISS | — |
| ITS-1231 | — | MISS | — |
| ITS-1232 | — | MISS | — |
| ITS-1233 | — | MISS | — |
| ITS-1234 | — | MISS | — |
| ITS-1235 | — | MISS | — |
| ITS-1236 | — | MISS | — |
| ITS-1237 | — | MISS | — |
| ITS-1238 | — | MISS | — |
| ITS-1239 | — | MISS | — |
| ITS-124 | — | MISS | — |
| ITS-1240 | — | MISS | — |
| ITS-1241 | — | MISS | — |
| ITS-1242 | — | MISS | — |
| ITS-1243 | — | MISS | — |
| ITS-1244 | — | MISS | — |
| ITS-1245 | — | MISS | — |
| ITS-1246 | — | MISS | — |
| ITS-1247 | — | MISS | — |
| ITS-1248 | — | MISS | — |
| ITS-1249 | — | MISS | — |
| ITS-125 | — | MISS | — |
| ITS-1250 | — | MISS | — |
| ITS-1251 | — | MISS | — |
| ITS-1252 | — | MISS | — |
| ITS-1253 | — | MISS | — |
| ITS-1254 | — | MISS | — |
| ITS-1255 | — | MISS | — |
| ITS-1256 | — | MISS | — |
| ITS-1257 | — | MISS | — |
| ITS-1258 | — | MISS | — |
| ITS-1259 | — | MISS | — |
| ITS-126 | — | MISS | — |
| ITS-1260 | — | MISS | — |
| ITS-1261 | — | MISS | — |
| ITS-1262 | — | MISS | — |
| ITS-1263 | — | MISS | — |
| ITS-1264 | — | MISS | — |
| ITS-1265 | — | MISS | — |
| ITS-1266 | — | MISS | — |
| ITS-1267 | — | MISS | — |
| ITS-1268 | — | MISS | — |
| ITS-1269 | — | MISS | — |
| ITS-127 | — | MISS | — |
| ITS-1270 | — | MISS | — |
| ITS-1271 | — | MISS | — |
| ITS-1272 | — | MISS | — |
| ITS-1273 | — | MISS | — |
| ITS-1274 | — | MISS | — |
| ITS-1275 | — | MISS | — |
| ITS-1276 | — | MISS | — |
| ITS-1277 | — | MISS | — |
| ITS-1278 | — | MISS | — |
| ITS-1279 | — | MISS | — |
| ITS-128 | — | MISS | — |
| ITS-1280 | — | MISS | — |
| ITS-1281 | — | MISS | — |
| ITS-1282 | — | MISS | — |
| ITS-1283 | — | MISS | — |
| ITS-1284 | — | MISS | — |
| ITS-1285 | — | MISS | — |
| ITS-1286 | — | MISS | — |
| ITS-1287 | — | MISS | — |
| ITS-1288 | — | MISS | — |
| ITS-1289 | — | MISS | — |
| ITS-129 | — | MISS | — |
| ITS-1290 | — | MISS | — |
| ITS-1291 | — | MISS | — |
| ITS-1292 | — | MISS | — |
| ITS-1293 | — | MISS | — |
| ITS-1294 | — | MISS | — |
| ITS-1295 | — | MISS | — |
| ITS-1296 | — | MISS | — |
| ITS-1297 | — | MISS | — |
| ITS-1298 | — | MISS | — |
| ITS-1299 | — | MISS | — |
| ITS-130 | — | MISS | — |
| ITS-1300 | — | MISS | — |
| ITS-1301 | — | MISS | — |
| ITS-1302 | — | MISS | — |
| ITS-1303 | — | MISS | — |
| ITS-1304 | — | MISS | — |
| ITS-1305 | — | MISS | — |
| ITS-1306 | — | MISS | — |
| ITS-1307 | — | MISS | — |
| ITS-1308 | — | MISS | — |
| ITS-1309 | — | MISS | — |
| ITS-131 | — | MISS | — |
| ITS-1310 | — | MISS | — |
| ITS-1311 | — | MISS | — |
| ITS-1312 | — | MISS | — |
| ITS-1313 | — | MISS | — |
| ITS-1314 | — | MISS | — |
| ITS-1315 | — | MISS | — |
| ITS-1316 | — | MISS | — |
| ITS-1317 | — | MISS | — |
| ITS-1318 | — | MISS | — |
| ITS-1319 | — | MISS | — |
| ITS-132 | — | MISS | — |
| ITS-1320 | — | MISS | — |
| ITS-1321 | — | MISS | — |
| ITS-1322 | — | MISS | — |
| ITS-1323 | — | MISS | — |
| ITS-1324 | — | MISS | — |
| ITS-1325 | — | MISS | — |
| ITS-1326 | — | MISS | — |
| ITS-1327 | — | MISS | — |
| ITS-1328 | — | MISS | — |
| ITS-1329 | — | MISS | — |
| ITS-133 | — | MISS | — |
| ITS-1330 | — | MISS | — |
| ITS-1331 | — | MISS | — |
| ITS-1332 | — | MISS | — |
| ITS-1333 | — | MISS | — |
| ITS-1334 | — | MISS | — |
| ITS-1335 | — | MISS | — |
| ITS-1336 | — | MISS | — |
| ITS-1337 | — | MISS | — |
| ITS-1338 | — | MISS | — |
| ITS-1339 | — | MISS | — |
| ITS-134 | — | MISS | — |
| ITS-1340 | — | MISS | — |
| ITS-1341 | — | MISS | — |
| ITS-1342 | — | MISS | — |
| ITS-1343 | — | MISS | — |
| ITS-1344 | — | MISS | — |
| ITS-1345 | — | MISS | — |
| ITS-1346 | — | MISS | — |
| ITS-1347 | — | MISS | — |
| ITS-1348 | — | MISS | — |
| ITS-1349 | — | MISS | — |
| ITS-135 | — | MISS | — |
| ITS-1350 | — | MISS | — |
| ITS-1351 | — | MISS | — |
| ITS-1352 | — | MISS | — |
| ITS-1353 | — | MISS | — |
| ITS-1354 | — | MISS | — |
| ITS-1355 | — | MISS | — |
| ITS-1356 | — | MISS | — |
| ITS-1357 | — | MISS | — |
| ITS-1358 | — | MISS | — |
| ITS-1359 | — | MISS | — |
| ITS-136 | — | MISS | — |
| ITS-1360 | — | MISS | — |
| ITS-1361 | — | MISS | — |
| ITS-1362 | — | MISS | — |
| ITS-1363 | — | MISS | — |
| ITS-1364 | — | MISS | — |
| ITS-1365 | — | MISS | — |
| ITS-1366 | — | MISS | — |
| ITS-1367 | — | MISS | — |
| ITS-1368 | — | MISS | — |
| ITS-1369 | — | MISS | — |
| ITS-137 | — | MISS | — |
| ITS-1370 | — | MISS | — |
| ITS-1371 | — | MISS | — |
| ITS-1372 | — | MISS | — |
| ITS-1373 | — | MISS | — |
| ITS-1374 | — | MISS | — |
| ITS-1375 | — | MISS | — |
| ITS-1376 | — | MISS | — |
| ITS-1377 | — | MISS | — |
| ITS-1378 | — | MISS | — |
| ITS-1379 | — | MISS | — |
| ITS-138 | — | MISS | — |
| ITS-1380 | — | MISS | — |
| ITS-1381 | — | MISS | — |
| ITS-1382 | — | MISS | — |
| ITS-1383 | — | MISS | — |
| ITS-1384 | — | MISS | — |
| ITS-1385 | — | MISS | — |
| ITS-1386 | — | MISS | — |
| ITS-1387 | — | MISS | — |
| ITS-1388 | — | MISS | — |
| ITS-1389 | — | MISS | — |
| ITS-139 | — | MISS | — |
| ITS-1390 | — | MISS | — |
| ITS-1391 | — | MISS | — |
| ITS-1392 | — | MISS | — |
| ITS-1393 | — | MISS | — |
| ITS-1394 | — | MISS | — |
| ITS-1395 | — | MISS | — |
| ITS-1396 | — | MISS | — |
| ITS-1397 | — | MISS | — |
| ITS-1398 | — | MISS | — |
| ITS-1399 | — | MISS | — |
| ITS-140 | — | MISS | — |
| ITS-1400 | — | MISS | — |
| ITS-1401 | — | MISS | — |
| ITS-1402 | — | MISS | — |
| ITS-1403 | — | MISS | — |
| ITS-1404 | — | MISS | — |
| ITS-1405 | — | MISS | — |
| ITS-1406 | — | MISS | — |
| ITS-1407 | — | MISS | — |
| ITS-1408 | — | MISS | — |
| ITS-1409 | — | MISS | — |
| ITS-141 | — | MISS | — |
| ITS-1410 | — | MISS | — |
| ITS-1411 | — | MISS | — |
| ITS-1412 | — | MISS | — |
| ITS-1413 | — | MISS | — |
| ITS-1414 | — | MISS | — |
| ITS-1415 | — | MISS | — |
| ITS-1416 | — | MISS | — |
| ITS-1417 | — | MISS | — |
| ITS-1418 | — | MISS | — |
| ITS-1419 | — | MISS | — |
| ITS-142 | — | MISS | — |
| ITS-1420 | — | MISS | — |
| ITS-1421 | — | MISS | — |
| ITS-1422 | — | MISS | — |
| ITS-1423 | — | MISS | — |
| ITS-1424 | — | MISS | — |
| ITS-1425 | — | MISS | — |
| ITS-1426 | — | MISS | — |
| ITS-1427 | — | MISS | — |
| ITS-1428 | — | MISS | — |
| ITS-1429 | — | MISS | — |
| ITS-143 | — | MISS | — |
| ITS-1430 | — | MISS | — |
| ITS-1431 | — | MISS | — |
| ITS-1432 | — | MISS | — |
| ITS-1433 | — | MISS | — |
| ITS-1434 | — | MISS | — |
| ITS-1435 | — | MISS | — |
| ITS-1436 | — | MISS | — |
| ITS-1437 | — | MISS | — |
| ITS-1438 | — | MISS | — |
| ITS-1439 | — | MISS | — |
| ITS-144 | — | MISS | — |
| ITS-1440 | — | MISS | — |
| ITS-1441 | — | MISS | — |
| ITS-1442 | — | MISS | — |
| ITS-1443 | — | MISS | — |
| ITS-1444 | — | MISS | — |
| ITS-1445 | — | MISS | — |
| ITS-1446 | — | MISS | — |
| ITS-1447 | — | MISS | — |
| ITS-1448 | — | MISS | — |
| ITS-1449 | — | MISS | — |
| ITS-145 | — | MISS | — |
| ITS-1450 | — | MISS | — |
| ITS-1451 | — | MISS | — |
| ITS-1452 | — | MISS | — |
| ITS-1453 | — | MISS | — |
| ITS-1454 | — | MISS | — |
| ITS-1455 | — | MISS | — |
| ITS-1456 | — | MISS | — |
| ITS-1457 | — | MISS | — |
| ITS-1458 | — | MISS | — |
| ITS-1459 | — | MISS | — |
| ITS-146 | — | MISS | — |
| ITS-1460 | — | MISS | — |
| ITS-1461 | — | MISS | — |
| ITS-1462 | — | MISS | — |
| ITS-1463 | — | MISS | — |
| ITS-1464 | — | MISS | — |
| ITS-1465 | — | MISS | — |
| ITS-1466 | — | MISS | — |
| ITS-1467 | — | MISS | — |
| ITS-1468 | — | MISS | — |
| ITS-1469 | — | MISS | — |
| ITS-147 | — | MISS | — |
| ITS-1470 | — | MISS | — |
| ITS-1471 | — | MISS | — |
| ITS-1472 | — | MISS | — |
| ITS-1473 | — | MISS | — |
| ITS-1474 | — | MISS | — |
| ITS-1475 | — | MISS | — |
| ITS-1476 | — | MISS | — |
| ITS-1477 | — | MISS | — |
| ITS-1478 | — | MISS | — |
| ITS-1479 | — | MISS | — |
| ITS-148 | — | MISS | — |
| ITS-1480 | — | MISS | — |
| ITS-1481 | — | MISS | — |
| ITS-1482 | — | MISS | — |
| ITS-1483 | — | MISS | — |
| ITS-1484 | — | MISS | — |
| ITS-1485 | — | MISS | — |
| ITS-1486 | — | MISS | — |
| ITS-1487 | — | MISS | — |
| ITS-1488 | — | MISS | — |
| ITS-1489 | — | MISS | — |
| ITS-149 | — | MISS | — |
| ITS-1490 | — | MISS | — |
| ITS-1491 | — | MISS | — |
| ITS-1492 | — | MISS | — |
| ITS-1493 | — | MISS | — |
| ITS-1494 | — | MISS | — |
| ITS-1495 | — | MISS | — |
| ITS-1496 | — | MISS | — |
| ITS-1497 | — | MISS | — |
| ITS-1498 | — | MISS | — |
| ITS-1499 | — | MISS | — |
| ITS-150 | — | MISS | — |
| ITS-1500 | — | MISS | — |
| ITS-1501 | — | MISS | — |
| ITS-1502 | — | MISS | — |
| ITS-1503 | — | MISS | — |
| ITS-1504 | — | MISS | — |
| ITS-1505 | — | MISS | — |
| ITS-1506 | — | MISS | — |
| ITS-1507 | — | MISS | — |
| ITS-1508 | — | MISS | — |
| ITS-1509 | — | MISS | — |
| ITS-151 | — | MISS | — |
| ITS-1510 | — | MISS | — |
| ITS-1511 | — | MISS | — |
| ITS-1512 | — | MISS | — |
| ITS-1513 | — | MISS | — |
| ITS-1514 | — | MISS | — |
| ITS-1515 | — | MISS | — |
| ITS-1516 | — | MISS | — |
| ITS-1517 | — | MISS | — |
| ITS-1518 | — | MISS | — |
| ITS-1519 | — | MISS | — |
| ITS-152 | — | MISS | — |
| ITS-1520 | — | MISS | — |
| ITS-1521 | — | MISS | — |
| ITS-1522 | — | MISS | — |
| ITS-1523 | — | MISS | — |
| ITS-1524 | — | MISS | — |
| ITS-1525 | — | MISS | — |
| ITS-1526 | — | MISS | — |
| ITS-1527 | — | MISS | — |
| ITS-1528 | — | MISS | — |
| ITS-1529 | — | MISS | — |
| ITS-153 | — | MISS | — |
| ITS-1530 | — | MISS | — |
| ITS-1531 | — | MISS | — |
| ITS-1532 | — | MISS | — |
| ITS-1533 | — | MISS | — |
| ITS-1534 | — | MISS | — |
| ITS-1535 | — | MISS | — |
| ITS-1536 | — | MISS | — |
| ITS-1537 | — | MISS | — |
| ITS-1538 | — | MISS | — |
| ITS-1539 | — | MISS | — |
| ITS-154 | — | MISS | — |
| ITS-1540 | — | MISS | — |
| ITS-1541 | — | MISS | — |
| ITS-1542 | — | MISS | — |
| ITS-1543 | — | MISS | — |
| ITS-1544 | — | MISS | — |
| ITS-1545 | — | MISS | — |
| ITS-1546 | — | MISS | — |
| ITS-1547 | — | MISS | — |
| ITS-1548 | — | MISS | — |
| ITS-1549 | — | MISS | — |
| ITS-155 | — | MISS | — |
| ITS-1550 | — | MISS | — |
| ITS-1551 | — | MISS | — |
| ITS-1552 | — | MISS | — |
| ITS-1553 | — | MISS | — |
| ITS-1554 | — | MISS | — |
| ITS-1555 | — | MISS | — |
| ITS-1556 | — | MISS | — |
| ITS-1557 | — | MISS | — |
| ITS-1558 | — | MISS | — |
| ITS-1559 | — | MISS | — |
| ITS-156 | — | MISS | — |
| ITS-1560 | — | MISS | — |
| ITS-1561 | — | MISS | — |
| ITS-1562 | — | MISS | — |
| ITS-1563 | — | MISS | — |
| ITS-1564 | — | MISS | — |
| ITS-1565 | — | MISS | — |
| ITS-1566 | — | MISS | — |
| ITS-1567 | — | MISS | — |
| ITS-1568 | — | MISS | — |
| ITS-1569 | — | MISS | — |
| ITS-157 | — | MISS | — |
| ITS-1570 | — | MISS | — |
| ITS-1571 | — | MISS | — |
| ITS-1572 | — | MISS | — |
| ITS-1573 | — | MISS | — |
| ITS-1574 | — | MISS | — |
| ITS-1575 | — | MISS | — |
| ITS-1576 | — | MISS | — |
| ITS-1577 | — | MISS | — |
| ITS-1578 | — | MISS | — |
| ITS-1579 | — | MISS | — |
| ITS-158 | — | MISS | — |
| ITS-1580 | — | MISS | — |
| ITS-1581 | — | MISS | — |
| ITS-1582 | — | MISS | — |
| ITS-1583 | — | MISS | — |
| ITS-1584 | — | MISS | — |
| ITS-1585 | — | MISS | — |
| ITS-1586 | — | MISS | — |
| ITS-1587 | — | MISS | — |
| ITS-1588 | — | MISS | — |
| ITS-1589 | — | MISS | — |
| ITS-159 | — | MISS | — |
| ITS-1590 | — | MISS | — |
| ITS-1591 | — | MISS | — |
| ITS-1592 | — | MISS | — |
| ITS-1593 | — | MISS | — |
| ITS-1594 | — | MISS | — |
| ITS-1595 | — | MISS | — |
| ITS-1596 | — | MISS | — |
| ITS-1597 | — | MISS | — |
| ITS-1598 | — | MISS | — |
| ITS-1599 | — | MISS | — |
| ITS-160 | — | MISS | — |
| ITS-1600 | — | MISS | — |
| ITS-1601 | — | MISS | — |
| ITS-1602 | — | MISS | — |
| ITS-1603 | — | MISS | — |
| ITS-1604 | — | MISS | — |
| ITS-1605 | — | MISS | — |
| ITS-1606 | — | MISS | — |
| ITS-1607 | — | MISS | — |
| ITS-1608 | — | MISS | — |
| ITS-1609 | — | MISS | — |
| ITS-161 | — | MISS | — |
| ITS-1610 | — | MISS | — |
| ITS-1611 | — | MISS | — |
| ITS-1612 | — | MISS | — |
| ITS-1613 | — | MISS | — |
| ITS-1614 | — | MISS | — |
| ITS-1615 | — | HIT | Semgrep |
| ITS-1616 | — | MISS | — |
| ITS-1617 | — | MISS | — |
| ITS-1618 | — | MISS | — |
| ITS-1619 | — | MISS | — |
| ITS-162 | — | MISS | — |
| ITS-1620 | — | MISS | — |
| ITS-1621 | — | MISS | — |
| ITS-1622 | — | MISS | — |
| ITS-1623 | — | MISS | — |
| ITS-1624 | — | MISS | — |
| ITS-1625 | — | MISS | — |
| ITS-1626 | — | MISS | — |
| ITS-1627 | — | MISS | — |
| ITS-1628 | — | MISS | — |
| ITS-1629 | — | MISS | — |
| ITS-163 | — | MISS | — |
| ITS-1630 | — | MISS | — |
| ITS-1631 | — | MISS | — |
| ITS-1632 | — | MISS | — |
| ITS-1633 | — | MISS | — |
| ITS-1634 | — | MISS | — |
| ITS-1635 | — | MISS | — |
| ITS-1636 | — | MISS | — |
| ITS-1637 | — | MISS | — |
| ITS-1638 | — | MISS | — |
| ITS-1639 | — | MISS | — |
| ITS-164 | — | MISS | — |
| ITS-1640 | — | MISS | — |
| ITS-1641 | — | MISS | — |
| ITS-1642 | — | MISS | — |
| ITS-1643 | — | MISS | — |
| ITS-1644 | — | MISS | — |
| ITS-1645 | — | MISS | — |
| ITS-1646 | — | MISS | — |
| ITS-1647 | — | MISS | — |
| ITS-1648 | — | MISS | — |
| ITS-1649 | — | MISS | — |
| ITS-165 | — | MISS | — |
| ITS-1650 | — | MISS | — |
| ITS-1651 | — | MISS | — |
| ITS-1652 | — | MISS | — |
| ITS-1653 | — | MISS | — |
| ITS-1654 | — | MISS | — |
| ITS-1655 | — | MISS | — |
| ITS-1656 | — | MISS | — |
| ITS-1657 | — | MISS | — |
| ITS-1658 | — | MISS | — |
| ITS-1659 | — | MISS | — |
| ITS-166 | — | MISS | — |
| ITS-1660 | — | MISS | — |
| ITS-1661 | — | MISS | — |
| ITS-1662 | — | MISS | — |
| ITS-1663 | — | MISS | — |
| ITS-1664 | — | MISS | — |
| ITS-1665 | — | MISS | — |
| ITS-1666 | — | HIT | Semgrep |
| ITS-1667 | — | MISS | — |
| ITS-1668 | — | MISS | — |
| ITS-1669 | — | MISS | — |
| ITS-167 | — | MISS | — |
| ITS-1670 | — | MISS | — |
| ITS-1671 | — | MISS | — |
| ITS-1672 | — | MISS | — |
| ITS-1673 | — | MISS | — |
| ITS-1674 | — | MISS | — |
| ITS-1675 | — | MISS | — |
| ITS-1676 | — | MISS | — |
| ITS-1677 | — | MISS | — |
| ITS-1678 | — | MISS | — |
| ITS-1679 | — | MISS | — |
| ITS-168 | — | MISS | — |
| ITS-1680 | — | MISS | — |
| ITS-1681 | — | HIT | Semgrep |
| ITS-1682 | — | MISS | — |
| ITS-1683 | — | MISS | — |
| ITS-1684 | — | MISS | — |
| ITS-1685 | — | MISS | — |
| ITS-1686 | — | MISS | — |
| ITS-1687 | — | MISS | — |
| ITS-1688 | — | MISS | — |
| ITS-1689 | — | MISS | — |
| ITS-169 | — | MISS | — |
| ITS-1690 | — | MISS | — |
| ITS-1691 | — | MISS | — |
| ITS-1692 | — | MISS | — |
| ITS-1693 | — | MISS | — |
| ITS-1694 | — | MISS | — |
| ITS-1695 | — | MISS | — |
| ITS-1696 | — | MISS | — |
| ITS-1697 | — | MISS | — |
| ITS-1698 | — | MISS | — |
| ITS-1699 | — | MISS | — |
| ITS-170 | — | MISS | — |
| ITS-1700 | — | MISS | — |
| ITS-1701 | — | MISS | — |
| ITS-1702 | — | MISS | — |
| ITS-1703 | — | MISS | — |
| ITS-1704 | — | MISS | — |
| ITS-1705 | — | MISS | — |
| ITS-1706 | — | MISS | — |
| ITS-1707 | — | MISS | — |
| ITS-1708 | — | MISS | — |
| ITS-1709 | — | MISS | — |
| ITS-171 | — | HIT | Semgrep |
| ITS-1710 | — | MISS | — |
| ITS-1711 | — | MISS | — |
| ITS-1712 | — | MISS | — |
| ITS-1713 | — | MISS | — |
| ITS-1714 | — | MISS | — |
| ITS-1715 | — | MISS | — |
| ITS-1716 | — | MISS | — |
| ITS-1717 | — | MISS | — |
| ITS-1718 | — | MISS | — |
| ITS-1719 | — | MISS | — |
| ITS-172 | — | MISS | — |
| ITS-1720 | — | MISS | — |
| ITS-1721 | — | MISS | — |
| ITS-1722 | — | MISS | — |
| ITS-1723 | — | MISS | — |
| ITS-1724 | — | MISS | — |
| ITS-1725 | — | MISS | — |
| ITS-1726 | — | MISS | — |
| ITS-1727 | — | MISS | — |
| ITS-1728 | — | MISS | — |
| ITS-1729 | — | MISS | — |
| ITS-173 | — | MISS | — |
| ITS-1730 | — | MISS | — |
| ITS-1731 | — | HIT | Semgrep |
| ITS-1732 | — | HIT | Semgrep |
| ITS-1733 | — | MISS | — |
| ITS-1734 | — | MISS | — |
| ITS-1735 | — | MISS | — |
| ITS-1736 | — | MISS | — |
| ITS-1737 | — | MISS | — |
| ITS-1738 | — | MISS | — |
| ITS-1739 | — | MISS | — |
| ITS-174 | — | MISS | — |
| ITS-1740 | — | MISS | — |
| ITS-1741 | — | HIT | Semgrep |
| ITS-1742 | — | MISS | — |
| ITS-1743 | — | MISS | — |
| ITS-1744 | — | MISS | — |
| ITS-1745 | — | MISS | — |
| ITS-1746 | — | MISS | — |
| ITS-1747 | — | MISS | — |
| ITS-1748 | — | MISS | — |
| ITS-1749 | — | MISS | — |
| ITS-175 | — | MISS | — |
| ITS-1750 | — | HIT | Semgrep |
| ITS-1751 | — | MISS | — |
| ITS-1752 | — | MISS | — |
| ITS-1753 | — | MISS | — |
| ITS-1754 | — | MISS | — |
| ITS-1755 | — | MISS | — |
| ITS-1756 | — | MISS | — |
| ITS-1757 | — | MISS | — |
| ITS-1758 | — | MISS | — |
| ITS-1759 | — | MISS | — |
| ITS-176 | — | MISS | — |
| ITS-1760 | — | MISS | — |
| ITS-1761 | — | MISS | — |
| ITS-1762 | — | MISS | — |
| ITS-1763 | — | MISS | — |
| ITS-1764 | — | MISS | — |
| ITS-1765 | — | MISS | — |
| ITS-1766 | — | MISS | — |
| ITS-1767 | — | MISS | — |
| ITS-1768 | — | MISS | — |
| ITS-1769 | — | MISS | — |
| ITS-177 | — | MISS | — |
| ITS-1770 | — | MISS | — |
| ITS-1771 | — | MISS | — |
| ITS-1772 | — | MISS | — |
| ITS-1773 | — | MISS | — |
| ITS-1774 | — | MISS | — |
| ITS-1775 | — | MISS | — |
| ITS-1776 | — | MISS | — |
| ITS-1777 | — | MISS | — |
| ITS-1778 | — | MISS | — |
| ITS-1779 | — | MISS | — |
| ITS-178 | — | MISS | — |
| ITS-1780 | — | MISS | — |
| ITS-1781 | — | MISS | — |
| ITS-1782 | — | MISS | — |
| ITS-1783 | — | MISS | — |
| ITS-1784 | — | MISS | — |
| ITS-1785 | — | MISS | — |
| ITS-1786 | — | MISS | — |
| ITS-1787 | — | MISS | — |
| ITS-1788 | — | MISS | — |
| ITS-1789 | — | MISS | — |
| ITS-179 | — | MISS | — |
| ITS-1790 | — | MISS | — |
| ITS-1791 | — | MISS | — |
| ITS-1792 | — | MISS | — |
| ITS-1793 | — | MISS | — |
| ITS-1794 | — | MISS | — |
| ITS-1795 | — | MISS | — |
| ITS-1796 | — | MISS | — |
| ITS-1797 | — | MISS | — |
| ITS-1798 | — | MISS | — |
| ITS-1799 | — | MISS | — |
| ITS-180 | — | MISS | — |
| ITS-1800 | — | MISS | — |
| ITS-1801 | — | MISS | — |
| ITS-1802 | — | MISS | — |
| ITS-1803 | — | MISS | — |
| ITS-1804 | — | MISS | — |
| ITS-1805 | — | MISS | — |
| ITS-181 | — | MISS | — |
| ITS-182 | — | MISS | — |
| ITS-183 | — | MISS | — |
| ITS-184 | — | MISS | — |
| ITS-185 | — | MISS | — |
| ITS-186 | — | MISS | — |
| ITS-187 | — | MISS | — |
| ITS-188 | — | MISS | — |
| ITS-189 | — | MISS | — |
| ITS-190 | — | MISS | — |
| ITS-191 | — | MISS | — |
| ITS-192 | — | MISS | — |
| ITS-193 | — | MISS | — |
| ITS-194 | — | MISS | — |
| ITS-195 | — | MISS | — |
| ITS-196 | — | MISS | — |
| ITS-197 | — | MISS | — |
| ITS-198 | — | MISS | — |
| ITS-199 | — | MISS | — |
| ITS-200 | — | MISS | — |
| ITS-201 | — | MISS | — |
| ITS-202 | — | MISS | — |
| ITS-203 | — | MISS | — |
| ITS-204 | — | MISS | — |
| ITS-205 | — | MISS | — |
| ITS-206 | — | MISS | — |
| ITS-207 | — | MISS | — |
| ITS-208 | — | MISS | — |
| ITS-209 | — | MISS | — |
| ITS-210 | — | MISS | — |
| ITS-211 | — | MISS | — |
| ITS-212 | — | MISS | — |
| ITS-213 | — | HIT | Semgrep |
| ITS-214 | — | MISS | — |
| ITS-215 | — | MISS | — |
| ITS-216 | — | MISS | — |
| ITS-217 | — | MISS | — |
| ITS-218 | — | MISS | — |
| ITS-219 | — | MISS | — |
| ITS-220 | — | MISS | — |
| ITS-221 | — | MISS | — |
| ITS-222 | — | MISS | — |
| ITS-223 | — | MISS | — |
| ITS-224 | — | HIT | Semgrep |
| ITS-225 | — | MISS | — |
| ITS-226 | — | MISS | — |
| ITS-227 | — | MISS | — |
| ITS-228 | — | MISS | — |
| ITS-229 | — | MISS | — |
| ITS-230 | — | MISS | — |
| ITS-231 | — | MISS | — |
| ITS-232 | — | MISS | — |
| ITS-233 | — | MISS | — |
| ITS-234 | — | MISS | — |
| ITS-235 | — | MISS | — |
| ITS-236 | — | MISS | — |
| ITS-237 | — | MISS | — |
| ITS-238 | — | MISS | — |
| ITS-239 | — | MISS | — |
| ITS-240 | — | MISS | — |
| ITS-241 | — | MISS | — |
| ITS-242 | — | MISS | — |
| ITS-243 | — | MISS | — |
| ITS-244 | — | MISS | — |
| ITS-245 | — | MISS | — |
| ITS-246 | — | MISS | — |
| ITS-247 | — | MISS | — |
| ITS-248 | — | MISS | — |
| ITS-249 | — | MISS | — |
| ITS-250 | — | MISS | — |
| ITS-251 | — | MISS | — |
| ITS-252 | — | MISS | — |
| ITS-253 | — | MISS | — |
| ITS-254 | — | MISS | — |
| ITS-255 | — | MISS | — |
| ITS-256 | — | MISS | — |
| ITS-257 | — | MISS | — |
| ITS-258 | — | MISS | — |
| ITS-259 | — | MISS | — |
| ITS-260 | — | MISS | — |
| ITS-261 | — | MISS | — |
| ITS-262 | — | MISS | — |
| ITS-263 | — | MISS | — |
| ITS-264 | — | HIT | Semgrep |
| ITS-265 | — | MISS | — |
| ITS-266 | — | HIT | Semgrep |
| ITS-267 | — | MISS | — |
| ITS-268 | — | MISS | — |
| ITS-269 | — | MISS | — |
| ITS-270 | — | MISS | — |
| ITS-271 | — | MISS | — |
| ITS-272 | — | MISS | — |
| ITS-273 | — | MISS | — |
| ITS-274 | — | MISS | — |
| ITS-275 | — | MISS | — |
| ITS-276 | — | MISS | — |
| ITS-277 | — | HIT | Semgrep |
| ITS-278 | — | MISS | — |
| ITS-279 | — | MISS | — |
| ITS-280 | — | MISS | — |
| ITS-281 | — | MISS | — |
| ITS-282 | — | MISS | — |
| ITS-283 | — | MISS | — |
| ITS-284 | — | MISS | — |
| ITS-285 | — | MISS | — |
| ITS-286 | — | MISS | — |
| ITS-287 | — | MISS | — |
| ITS-288 | — | MISS | — |
| ITS-289 | — | MISS | — |
| ITS-290 | — | MISS | — |
| ITS-291 | — | MISS | — |
| ITS-292 | — | MISS | — |
| ITS-293 | — | MISS | — |
| ITS-294 | — | MISS | — |
| ITS-295 | — | MISS | — |
| ITS-296 | — | MISS | — |
| ITS-297 | — | MISS | — |
| ITS-298 | — | MISS | — |
| ITS-299 | — | MISS | — |
| ITS-300 | — | MISS | — |
| ITS-301 | — | MISS | — |
| ITS-302 | — | MISS | — |
| ITS-303 | — | MISS | — |
| ITS-304 | — | MISS | — |
| ITS-305 | — | MISS | — |
| ITS-306 | — | MISS | — |
| ITS-307 | — | MISS | — |
| ITS-308 | — | MISS | — |
| ITS-309 | — | MISS | — |
| ITS-310 | — | MISS | — |
| ITS-311 | — | MISS | — |
| ITS-312 | — | HIT | Semgrep |
| ITS-313 | — | MISS | — |
| ITS-314 | — | MISS | — |
| ITS-315 | — | MISS | — |
| ITS-316 | — | HIT | Semgrep |
| ITS-317 | — | HIT | Semgrep |
| ITS-318 | — | MISS | — |
| ITS-319 | — | MISS | — |
| ITS-320 | — | MISS | — |
| ITS-321 | — | MISS | — |
| ITS-322 | — | MISS | — |
| ITS-323 | — | MISS | — |
| ITS-324 | — | MISS | — |
| ITS-325 | — | MISS | — |
| ITS-326 | — | MISS | — |
| ITS-327 | — | MISS | — |
| ITS-328 | — | MISS | — |
| ITS-329 | — | MISS | — |
| ITS-330 | — | MISS | — |
| ITS-331 | — | HIT | Semgrep |
| ITS-332 | — | HIT | Semgrep |
| ITS-333 | — | MISS | — |
| ITS-334 | — | HIT | Semgrep |
| ITS-335 | — | MISS | — |
| ITS-336 | — | MISS | — |
| ITS-337 | — | MISS | — |
| ITS-338 | — | MISS | — |
| ITS-339 | — | MISS | — |
| ITS-340 | — | MISS | — |
| ITS-341 | — | MISS | — |
| ITS-342 | — | MISS | — |
| ITS-343 | — | MISS | — |
| ITS-344 | — | MISS | — |
| ITS-345 | — | MISS | — |
| ITS-346 | — | MISS | — |
| ITS-347 | — | MISS | — |
| ITS-348 | — | MISS | — |
| ITS-349 | — | MISS | — |
| ITS-350 | — | MISS | — |
| ITS-351 | — | MISS | — |
| ITS-352 | — | MISS | — |
| ITS-353 | — | MISS | — |
| ITS-354 | — | MISS | — |
| ITS-355 | — | MISS | — |
| ITS-356 | — | MISS | — |
| ITS-357 | — | MISS | — |
| ITS-358 | — | MISS | — |
| ITS-359 | — | MISS | — |
| ITS-360 | — | MISS | — |
| ITS-361 | — | MISS | — |
| ITS-362 | — | MISS | — |
| ITS-363 | — | MISS | — |
| ITS-364 | — | MISS | — |
| ITS-365 | — | MISS | — |
| ITS-366 | — | MISS | — |
| ITS-367 | — | MISS | — |
| ITS-368 | — | MISS | — |
| ITS-369 | — | MISS | — |
| ITS-370 | — | MISS | — |
| ITS-371 | — | MISS | — |
| ITS-372 | — | MISS | — |
| ITS-373 | — | MISS | — |
| ITS-374 | — | MISS | — |
| ITS-375 | — | MISS | — |
| ITS-376 | — | MISS | — |
| ITS-377 | — | MISS | — |
| ITS-378 | — | MISS | — |
| ITS-379 | — | MISS | — |
| ITS-380 | — | MISS | — |
| ITS-381 | — | MISS | — |
| ITS-382 | — | MISS | — |
| ITS-383 | — | MISS | — |
| ITS-384 | — | MISS | — |
| ITS-385 | — | MISS | — |
| ITS-386 | — | MISS | — |
| ITS-387 | — | MISS | — |
| ITS-388 | — | MISS | — |
| ITS-389 | — | MISS | — |
| ITS-390 | — | MISS | — |
| ITS-391 | — | MISS | — |
| ITS-392 | — | MISS | — |
| ITS-393 | — | MISS | — |
| ITS-394 | — | MISS | — |
| ITS-395 | — | MISS | — |
| ITS-396 | — | MISS | — |
| ITS-397 | — | MISS | — |
| ITS-398 | — | MISS | — |
| ITS-399 | — | MISS | — |
| ITS-400 | — | MISS | — |
| ITS-401 | — | MISS | — |
| ITS-402 | — | MISS | — |
| ITS-403 | — | MISS | — |
| ITS-404 | — | HIT | Semgrep |
| ITS-405 | — | MISS | — |
| ITS-406 | — | MISS | — |
| ITS-407 | — | MISS | — |
| ITS-408 | — | MISS | — |
| ITS-409 | — | MISS | — |
| ITS-410 | — | MISS | — |
| ITS-411 | — | MISS | — |
| ITS-412 | — | MISS | — |
| ITS-413 | — | MISS | — |
| ITS-414 | — | MISS | — |
| ITS-415 | — | MISS | — |
| ITS-416 | — | MISS | — |
| ITS-417 | — | HIT | Semgrep |
| ITS-418 | — | HIT | Semgrep |
| ITS-419 | — | MISS | — |
| ITS-420 | — | MISS | — |
| ITS-421 | — | MISS | — |
| ITS-422 | — | MISS | — |
| ITS-423 | — | MISS | — |
| ITS-424 | — | MISS | — |
| ITS-425 | — | MISS | — |
| ITS-426 | — | MISS | — |
| ITS-427 | — | MISS | — |
| ITS-428 | — | MISS | — |
| ITS-429 | — | MISS | — |
| ITS-430 | — | MISS | — |
| ITS-431 | — | HIT | Semgrep |
| ITS-432 | — | MISS | — |
| ITS-433 | — | MISS | — |
| ITS-434 | — | MISS | — |
| ITS-435 | — | MISS | — |
| ITS-436 | — | MISS | — |
| ITS-437 | — | MISS | — |
| ITS-438 | — | MISS | — |
| ITS-439 | — | MISS | — |
| ITS-440 | — | MISS | — |
| ITS-441 | — | MISS | — |
| ITS-442 | — | MISS | — |
| ITS-443 | — | MISS | — |
| ITS-444 | — | MISS | — |
| ITS-445 | — | MISS | — |
| ITS-446 | — | MISS | — |
| ITS-447 | — | MISS | — |
| ITS-448 | — | MISS | — |
| ITS-449 | — | MISS | — |
| ITS-450 | — | MISS | — |
| ITS-451 | — | MISS | — |
| ITS-452 | — | MISS | — |
| ITS-453 | — | MISS | — |
| ITS-454 | — | MISS | — |
| ITS-455 | — | HIT | Semgrep |
| ITS-456 | — | MISS | — |
| ITS-457 | — | MISS | — |
| ITS-458 | — | MISS | — |
| ITS-459 | — | MISS | — |
| ITS-460 | — | MISS | — |
| ITS-461 | — | MISS | — |
| ITS-462 | — | MISS | — |
| ITS-463 | — | MISS | — |
| ITS-464 | — | HIT | Semgrep |
| ITS-465 | — | HIT | Semgrep |
| ITS-466 | — | HIT | Semgrep |
| ITS-467 | — | HIT | Semgrep |
| ITS-468 | — | MISS | — |
| ITS-469 | — | MISS | — |
| ITS-470 | — | MISS | — |
| ITS-471 | — | MISS | — |
| ITS-472 | — | MISS | — |
| ITS-473 | — | MISS | — |
| ITS-474 | — | MISS | — |
| ITS-475 | — | MISS | — |
| ITS-476 | — | MISS | — |
| ITS-477 | — | MISS | — |
| ITS-478 | — | MISS | — |
| ITS-479 | — | MISS | — |
| ITS-480 | — | MISS | — |
| ITS-481 | — | MISS | — |
| ITS-482 | — | MISS | — |
| ITS-483 | — | MISS | — |
| ITS-484 | — | MISS | — |
| ITS-485 | — | MISS | — |
| ITS-486 | — | MISS | — |
| ITS-487 | — | MISS | — |
| ITS-488 | — | MISS | — |
| ITS-489 | — | MISS | — |
| ITS-490 | — | HIT | Semgrep |
| ITS-491 | — | MISS | — |
| ITS-492 | — | MISS | — |
| ITS-493 | — | MISS | — |
| ITS-494 | — | MISS | — |
| ITS-495 | — | HIT | Semgrep |
| ITS-496 | — | HIT | Semgrep |
| ITS-497 | — | HIT | Semgrep |
| ITS-498 | — | HIT | Semgrep |
| ITS-499 | — | MISS | — |
| ITS-500 | — | MISS | — |
| ITS-501 | — | MISS | — |
| ITS-502 | — | MISS | — |
| ITS-503 | — | MISS | — |
| ITS-504 | — | MISS | — |
| ITS-505 | — | MISS | — |
| ITS-506 | — | MISS | — |
| ITS-507 | — | MISS | — |
| ITS-508 | — | MISS | — |
| ITS-509 | — | MISS | — |
| ITS-510 | — | MISS | — |
| ITS-511 | — | HIT | Semgrep |
| ITS-512 | — | MISS | — |
| ITS-513 | — | MISS | — |
| ITS-514 | — | MISS | — |
| ITS-515 | — | MISS | — |
| ITS-516 | — | MISS | — |
| ITS-517 | — | MISS | — |
| ITS-518 | — | MISS | — |
| ITS-519 | — | MISS | — |
| ITS-520 | — | MISS | — |
| ITS-521 | — | MISS | — |
| ITS-522 | — | MISS | — |
| ITS-523 | — | MISS | — |
| ITS-524 | — | MISS | — |
| ITS-525 | — | MISS | — |
| ITS-526 | — | MISS | — |
| ITS-527 | — | MISS | — |
| ITS-528 | — | MISS | — |
| ITS-529 | — | MISS | — |
| ITS-530 | — | MISS | — |
| ITS-531 | — | MISS | — |
| ITS-532 | — | MISS | — |
| ITS-533 | — | MISS | — |
| ITS-534 | — | MISS | — |
| ITS-535 | — | MISS | — |
| ITS-536 | — | MISS | — |
| ITS-537 | — | MISS | — |
| ITS-538 | — | MISS | — |
| ITS-539 | — | MISS | — |
| ITS-540 | — | MISS | — |
| ITS-541 | — | MISS | — |
| ITS-542 | — | MISS | — |
| ITS-543 | — | MISS | — |
| ITS-544 | — | MISS | — |
| ITS-545 | — | MISS | — |
| ITS-546 | — | MISS | — |
| ITS-547 | — | MISS | — |
| ITS-548 | — | MISS | — |
| ITS-549 | — | MISS | — |
| ITS-550 | — | MISS | — |
| ITS-551 | — | MISS | — |
| ITS-552 | — | MISS | — |
| ITS-553 | — | MISS | — |
| ITS-554 | — | MISS | — |
| ITS-555 | — | MISS | — |
| ITS-556 | — | MISS | — |
| ITS-557 | — | MISS | — |
| ITS-558 | — | MISS | — |
| ITS-559 | — | MISS | — |
| ITS-560 | — | MISS | — |
| ITS-561 | — | MISS | — |
| ITS-562 | — | MISS | — |
| ITS-563 | — | MISS | — |
| ITS-564 | — | MISS | — |
| ITS-565 | — | MISS | — |
| ITS-566 | — | MISS | — |
| ITS-567 | — | MISS | — |
| ITS-568 | — | MISS | — |
| ITS-569 | — | MISS | — |
| ITS-570 | — | MISS | — |
| ITS-571 | — | MISS | — |
| ITS-572 | — | MISS | — |
| ITS-573 | — | MISS | — |
| ITS-574 | — | MISS | — |
| ITS-575 | — | MISS | — |
| ITS-576 | — | MISS | — |
| ITS-577 | — | MISS | — |
| ITS-578 | — | MISS | — |
| ITS-579 | — | MISS | — |
| ITS-580 | — | MISS | — |
| ITS-581 | — | MISS | — |
| ITS-582 | — | MISS | — |
| ITS-583 | — | MISS | — |
| ITS-584 | — | MISS | — |
| ITS-585 | — | MISS | — |
| ITS-586 | — | MISS | — |
| ITS-587 | — | MISS | — |
| ITS-588 | — | MISS | — |
| ITS-589 | — | MISS | — |
| ITS-590 | — | MISS | — |
| ITS-591 | — | MISS | — |
| ITS-592 | — | MISS | — |
| ITS-593 | — | MISS | — |
| ITS-594 | — | MISS | — |
| ITS-595 | — | MISS | — |
| ITS-596 | — | MISS | — |
| ITS-597 | — | MISS | — |
| ITS-598 | — | MISS | — |
| ITS-599 | — | MISS | — |
| ITS-600 | — | MISS | — |
| ITS-601 | — | MISS | — |
| ITS-602 | — | MISS | — |
| ITS-603 | — | MISS | — |
| ITS-604 | — | MISS | — |
| ITS-605 | — | MISS | — |
| ITS-606 | — | MISS | — |
| ITS-607 | — | MISS | — |
| ITS-608 | — | MISS | — |
| ITS-609 | — | MISS | — |
| ITS-610 | — | MISS | — |
| ITS-611 | — | MISS | — |
| ITS-612 | — | MISS | — |
| ITS-613 | — | MISS | — |
| ITS-614 | — | MISS | — |
| ITS-615 | — | MISS | — |
| ITS-616 | — | MISS | — |
| ITS-617 | — | MISS | — |
| ITS-618 | — | MISS | — |
| ITS-619 | — | MISS | — |
| ITS-620 | — | MISS | — |
| ITS-621 | — | MISS | — |
| ITS-622 | — | MISS | — |
| ITS-623 | — | MISS | — |
| ITS-624 | — | MISS | — |
| ITS-625 | — | MISS | — |
| ITS-626 | — | MISS | — |
| ITS-627 | — | MISS | — |
| ITS-628 | — | MISS | — |
| ITS-629 | — | MISS | — |
| ITS-630 | — | MISS | — |
| ITS-631 | — | MISS | — |
| ITS-632 | — | MISS | — |
| ITS-633 | — | MISS | — |
| ITS-634 | — | MISS | — |
| ITS-635 | — | MISS | — |
| ITS-636 | — | MISS | — |
| ITS-637 | — | MISS | — |
| ITS-638 | — | MISS | — |
| ITS-639 | — | MISS | — |
| ITS-640 | — | MISS | — |
| ITS-641 | — | MISS | — |
| ITS-642 | — | MISS | — |
| ITS-643 | — | MISS | — |
| ITS-644 | — | MISS | — |
| ITS-645 | — | MISS | — |
| ITS-646 | — | MISS | — |
| ITS-647 | — | MISS | — |
| ITS-648 | — | MISS | — |
| ITS-649 | — | MISS | — |
| ITS-650 | — | MISS | — |
| ITS-651 | — | MISS | — |
| ITS-652 | — | MISS | — |
| ITS-653 | — | MISS | — |
| ITS-654 | — | MISS | — |
| ITS-655 | — | MISS | — |
| ITS-656 | — | MISS | — |
| ITS-657 | — | MISS | — |
| ITS-658 | — | MISS | — |
| ITS-659 | — | MISS | — |
| ITS-660 | — | MISS | — |
| ITS-661 | — | MISS | — |
| ITS-662 | — | MISS | — |
| ITS-663 | — | MISS | — |
| ITS-664 | — | MISS | — |
| ITS-665 | — | MISS | — |
| ITS-666 | — | MISS | — |
| ITS-667 | — | MISS | — |
| ITS-668 | — | MISS | — |
| ITS-669 | — | MISS | — |
| ITS-670 | — | MISS | — |
| ITS-671 | — | MISS | — |
| ITS-672 | — | MISS | — |
| ITS-673 | — | MISS | — |
| ITS-674 | — | MISS | — |
| ITS-675 | — | MISS | — |
| ITS-676 | — | MISS | — |
| ITS-677 | — | MISS | — |
| ITS-678 | — | MISS | — |
| ITS-679 | — | MISS | — |
| ITS-680 | — | MISS | — |
| ITS-681 | — | MISS | — |
| ITS-682 | — | MISS | — |
| ITS-683 | — | MISS | — |
| ITS-684 | — | MISS | — |
| ITS-685 | — | MISS | — |
| ITS-686 | — | MISS | — |
| ITS-687 | — | MISS | — |
| ITS-688 | — | MISS | — |
| ITS-689 | — | MISS | — |
| ITS-690 | — | MISS | — |
| ITS-691 | — | MISS | — |
| ITS-692 | — | MISS | — |
| ITS-693 | — | MISS | — |
| ITS-694 | — | MISS | — |
| ITS-695 | — | MISS | — |
| ITS-696 | — | MISS | — |
| ITS-697 | — | MISS | — |
| ITS-698 | — | MISS | — |
| ITS-699 | — | MISS | — |
| ITS-700 | — | MISS | — |
| ITS-701 | — | MISS | — |
| ITS-702 | — | MISS | — |
| ITS-703 | — | MISS | — |
| ITS-704 | — | MISS | — |
| ITS-705 | — | MISS | — |
| ITS-706 | — | MISS | — |
| ITS-707 | — | MISS | — |
| ITS-708 | — | MISS | — |
| ITS-709 | — | MISS | — |
| ITS-710 | — | MISS | — |
| ITS-711 | — | MISS | — |
| ITS-712 | — | MISS | — |
| ITS-713 | — | MISS | — |
| ITS-714 | — | MISS | — |
| ITS-715 | — | MISS | — |
| ITS-716 | — | MISS | — |
| ITS-717 | — | MISS | — |
| ITS-718 | — | MISS | — |
| ITS-719 | — | MISS | — |
| ITS-720 | — | MISS | — |
| ITS-721 | — | MISS | — |
| ITS-722 | — | MISS | — |
| ITS-723 | — | MISS | — |
| ITS-724 | — | MISS | — |
| ITS-725 | — | MISS | — |
| ITS-726 | — | MISS | — |
| ITS-727 | — | MISS | — |
| ITS-728 | — | MISS | — |
| ITS-729 | — | MISS | — |
| ITS-730 | — | MISS | — |
| ITS-731 | — | MISS | — |
| ITS-732 | — | MISS | — |
| ITS-733 | — | MISS | — |
| ITS-734 | — | MISS | — |
| ITS-735 | — | MISS | — |
| ITS-736 | — | MISS | — |
| ITS-737 | — | MISS | — |
| ITS-738 | — | MISS | — |
| ITS-739 | — | MISS | — |
| ITS-740 | — | MISS | — |
| ITS-741 | — | MISS | — |
| ITS-742 | — | MISS | — |
| ITS-743 | — | MISS | — |
| ITS-744 | — | MISS | — |
| ITS-745 | — | MISS | — |
| ITS-746 | — | MISS | — |
| ITS-747 | — | MISS | — |
| ITS-748 | — | MISS | — |
| ITS-749 | — | MISS | — |
| ITS-750 | — | MISS | — |
| ITS-751 | — | MISS | — |
| ITS-752 | — | MISS | — |
| ITS-753 | — | MISS | — |
| ITS-754 | — | MISS | — |
| ITS-755 | — | MISS | — |
| ITS-756 | — | MISS | — |
| ITS-757 | — | MISS | — |
| ITS-758 | — | MISS | — |
| ITS-759 | — | MISS | — |
| ITS-760 | — | MISS | — |
| ITS-761 | — | MISS | — |
| ITS-762 | — | MISS | — |
| ITS-763 | — | MISS | — |
| ITS-764 | — | MISS | — |
| ITS-765 | — | MISS | — |
| ITS-766 | — | MISS | — |
| ITS-767 | — | MISS | — |
| ITS-768 | — | MISS | — |
| ITS-769 | — | MISS | — |
| ITS-770 | — | MISS | — |
| ITS-771 | — | MISS | — |
| ITS-772 | — | MISS | — |
| ITS-773 | — | MISS | — |
| ITS-774 | — | MISS | — |
| ITS-775 | — | MISS | — |
| ITS-776 | — | MISS | — |
| ITS-777 | — | MISS | — |
| ITS-778 | — | MISS | — |
| ITS-779 | — | MISS | — |
| ITS-780 | — | MISS | — |
| ITS-781 | — | MISS | — |
| ITS-782 | — | MISS | — |
| ITS-783 | — | MISS | — |
| ITS-784 | — | MISS | — |
| ITS-785 | — | MISS | — |
| ITS-786 | — | MISS | — |
| ITS-787 | — | MISS | — |
| ITS-788 | — | MISS | — |
| ITS-789 | — | MISS | — |
| ITS-790 | — | MISS | — |
| ITS-791 | — | MISS | — |
| ITS-792 | — | MISS | — |
| ITS-793 | — | MISS | — |
| ITS-794 | — | MISS | — |
| ITS-795 | — | MISS | — |
| ITS-796 | — | MISS | — |
| ITS-797 | — | MISS | — |
| ITS-798 | — | MISS | — |
| ITS-799 | — | MISS | — |
| ITS-800 | — | MISS | — |
| ITS-801 | — | MISS | — |
| ITS-802 | — | MISS | — |
| ITS-803 | — | MISS | — |
| ITS-804 | — | MISS | — |
| ITS-805 | — | MISS | — |
| ITS-806 | — | MISS | — |
| ITS-807 | — | MISS | — |
| ITS-808 | — | MISS | — |
| ITS-809 | — | MISS | — |
| ITS-810 | — | MISS | — |
| ITS-811 | — | MISS | — |
| ITS-812 | — | MISS | — |
| ITS-813 | — | MISS | — |
| ITS-814 | — | MISS | — |
| ITS-815 | — | MISS | — |
| ITS-816 | — | MISS | — |
| ITS-817 | — | MISS | — |
| ITS-818 | — | MISS | — |
| ITS-819 | — | MISS | — |
| ITS-820 | — | MISS | — |
| ITS-821 | — | MISS | — |
| ITS-822 | — | MISS | — |
| ITS-823 | — | MISS | — |
| ITS-824 | — | MISS | — |
| ITS-825 | — | MISS | — |
| ITS-826 | — | MISS | — |
| ITS-827 | — | MISS | — |
| ITS-828 | — | MISS | — |
| ITS-829 | — | MISS | — |
| ITS-830 | — | MISS | — |
| ITS-831 | — | MISS | — |
| ITS-832 | — | MISS | — |
| ITS-833 | — | MISS | — |
| ITS-834 | — | MISS | — |
| ITS-835 | — | MISS | — |
| ITS-836 | — | MISS | — |
| ITS-837 | — | MISS | — |
| ITS-838 | — | MISS | — |
| ITS-839 | — | MISS | — |
| ITS-840 | — | MISS | — |
| ITS-841 | — | MISS | — |
| ITS-842 | — | MISS | — |
| ITS-843 | — | MISS | — |
| ITS-844 | — | MISS | — |
| ITS-845 | — | MISS | — |
| ITS-846 | — | MISS | — |
| ITS-847 | — | MISS | — |
| ITS-848 | — | MISS | — |
| ITS-849 | — | MISS | — |
| ITS-850 | — | MISS | — |
| ITS-851 | — | MISS | — |
| ITS-852 | — | MISS | — |
| ITS-853 | — | MISS | — |
| ITS-854 | — | MISS | — |
| ITS-855 | — | MISS | — |
| ITS-856 | — | MISS | — |
| ITS-857 | — | MISS | — |
| ITS-858 | — | MISS | — |
| ITS-859 | — | MISS | — |
| ITS-860 | — | MISS | — |
| ITS-861 | — | MISS | — |
| ITS-862 | — | MISS | — |
| ITS-863 | — | MISS | — |
| ITS-864 | — | MISS | — |
| ITS-865 | — | MISS | — |
| ITS-866 | — | MISS | — |
| ITS-867 | — | MISS | — |
| ITS-868 | — | MISS | — |
| ITS-869 | — | MISS | — |
| ITS-870 | — | MISS | — |
| ITS-871 | — | MISS | — |
| ITS-872 | — | MISS | — |
| ITS-873 | — | MISS | — |
| ITS-874 | — | MISS | — |
| ITS-875 | — | MISS | — |
| ITS-876 | — | MISS | — |
| ITS-877 | — | MISS | — |
| ITS-878 | — | MISS | — |
| ITS-879 | — | MISS | — |
| ITS-880 | — | MISS | — |
| ITS-881 | — | MISS | — |
| ITS-882 | — | MISS | — |
| ITS-883 | — | MISS | — |
| ITS-884 | — | MISS | — |
| ITS-885 | — | MISS | — |
| ITS-886 | — | MISS | — |
| ITS-887 | — | MISS | — |
| ITS-888 | — | MISS | — |
| ITS-889 | — | MISS | — |
| ITS-890 | — | MISS | — |
| ITS-891 | — | MISS | — |
| ITS-892 | — | MISS | — |
| ITS-893 | — | MISS | — |
| ITS-894 | — | MISS | — |
| ITS-895 | — | MISS | — |
| ITS-896 | — | MISS | — |
| ITS-897 | — | MISS | — |
| ITS-898 | — | MISS | — |
| ITS-899 | — | MISS | — |
| ITS-900 | — | MISS | — |
| ITS-901 | — | MISS | — |
| ITS-902 | — | MISS | — |
| ITS-903 | — | MISS | — |
| ITS-904 | — | MISS | — |
| ITS-905 | — | MISS | — |
| ITS-906 | — | MISS | — |
| ITS-907 | — | MISS | — |
| ITS-908 | — | MISS | — |
| ITS-909 | — | MISS | — |
| ITS-910 | — | MISS | — |
| ITS-911 | — | MISS | — |
| ITS-912 | — | MISS | — |
| ITS-913 | — | MISS | — |
| ITS-914 | — | MISS | — |
| ITS-915 | — | MISS | — |
| ITS-916 | — | MISS | — |
| ITS-917 | — | MISS | — |
| ITS-918 | — | MISS | — |
| ITS-919 | — | MISS | — |
| ITS-920 | — | MISS | — |
| ITS-921 | — | MISS | — |
| ITS-922 | — | MISS | — |
| ITS-923 | — | MISS | — |
| ITS-924 | — | MISS | — |
| ITS-925 | — | MISS | — |
| ITS-926 | — | MISS | — |
| ITS-927 | — | MISS | — |
| ITS-928 | — | MISS | — |
| ITS-929 | — | MISS | — |
| ITS-930 | — | MISS | — |
| ITS-931 | — | MISS | — |
| ITS-932 | — | MISS | — |
| ITS-933 | — | MISS | — |
| ITS-934 | — | MISS | — |
| ITS-935 | — | MISS | — |
| ITS-936 | — | MISS | — |
| ITS-937 | — | MISS | — |
| ITS-938 | — | MISS | — |
| ITS-939 | — | MISS | — |
| ITS-940 | — | MISS | — |
| ITS-941 | — | MISS | — |
| ITS-942 | — | MISS | — |
| ITS-943 | — | MISS | — |
| ITS-944 | — | MISS | — |
| ITS-945 | — | MISS | — |
| ITS-946 | — | MISS | — |
| ITS-947 | — | MISS | — |
| ITS-948 | — | MISS | — |
| ITS-949 | — | MISS | — |
| ITS-950 | — | MISS | — |
| ITS-951 | — | MISS | — |
| ITS-952 | — | MISS | — |
| ITS-953 | — | MISS | — |
| ITS-954 | — | MISS | — |
| ITS-955 | — | MISS | — |
| ITS-956 | — | MISS | — |
| ITS-957 | — | MISS | — |
| ITS-958 | — | MISS | — |
| ITS-959 | — | MISS | — |
| ITS-960 | — | MISS | — |
| ITS-961 | — | MISS | — |
| ITS-962 | — | MISS | — |
| ITS-963 | — | MISS | — |
| ITS-964 | — | MISS | — |
| ITS-965 | — | MISS | — |
| ITS-966 | — | MISS | — |
| ITS-967 | — | MISS | — |
| ITS-968 | — | MISS | — |
| ITS-969 | — | MISS | — |
| ITS-970 | — | MISS | — |
| ITS-971 | — | MISS | — |
| ITS-972 | — | MISS | — |
| ITS-973 | — | MISS | — |
| ITS-974 | — | MISS | — |
| ITS-975 | — | MISS | — |
| ITS-976 | — | MISS | — |
| ITS-977 | — | MISS | — |
| ITS-978 | — | MISS | — |
| ITS-979 | — | MISS | — |
| ITS-980 | — | MISS | — |
| ITS-981 | — | MISS | — |
| ITS-982 | — | MISS | — |
| ITS-983 | — | MISS | — |
| ITS-984 | — | MISS | — |
| ITS-985 | — | MISS | — |
| ITS-986 | — | MISS | — |
| ITS-987 | — | MISS | — |
| ITS-988 | — | MISS | — |
| ITS-989 | — | MISS | — |
| ITS-990 | — | MISS | — |
| ITS-991 | — | MISS | — |
| ITS-992 | — | MISS | — |
| ITS-993 | — | MISS | — |
| ITS-994 | — | MISS | — |
| ITS-995 | — | MISS | — |
| ITS-996 | — | MISS | — |
| ITS-997 | — | MISS | — |
| ITS-998 | — | MISS | — |
| ITS-999 | — | MISS | — |
| JAVA-001 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| JAVA-002 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| JAVA-003 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| JAVA-004 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| JAVA-005 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| JAVA-006 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| JAVA-007 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| JAVA-008 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| JAVA-009 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| JAVA-010 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| JAVA-011 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| JAVA-012 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| JAVA-013 | `core/gold-standard-testbed/multi_lang_vulnerable/java_vulnerable.java` | HIT | Semgrep + marker |
| JAVA-014 | `core/gold-standard-testbed/multi_lang_vulnerable/java_vulnerable.java` | HIT | Semgrep + marker |
| JAVA-015 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| JAVA-016 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| JAVA-017 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| JAVA-018 | `core/gold-standard-testbed/multi_lang_vulnerable/java_vulnerable.java` | HIT | Semgrep + marker |
| JAVA-019 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| JAVA-020 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| JAVA-021 | — | MISS | — |
| JAVA-022 | — | MISS | — |
| JAVA-023 | — | MISS | — |
| JAVA-024 | — | MISS | — |
| JAVA-025 | — | MISS | — |
| JAVA-026 | — | MISS | — |
| JAVA-027 | — | MISS | — |
| JAVA-028 | — | MISS | — |
| JAVA-029 | — | MISS | — |
| JAVA-030 | — | MISS | — |
| JAVA-031 | — | MISS | — |
| JAVA-032 | — | MISS | — |
| JAVA-033 | — | MISS | — |
| JAVA-034 | — | MISS | — |
| JAVA-035 | — | MISS | — |
| JAVA-036 | — | MISS | — |
| JAVA-037 | — | MISS | — |
| JAVA-038 | — | MISS | — |
| JAVA-039 | — | MISS | — |
| JAVA-040 | — | MISS | — |
| JAVA-041 | — | MISS | — |
| JAVA-042 | — | MISS | — |
| JAVA-043 | — | MISS | — |
| JAVA-044 | — | MISS | — |
| JAVA-045 | — | MISS | — |
| JAVA-046 | — | MISS | — |
| JAVA-047 | — | MISS | — |
| JAVA-048 | — | MISS | — |
| JAVA-049 | — | MISS | — |
| JAVA-050 | — | MISS | — |
| JAVA-051 | — | MISS | — |
| JAVA-052 | — | MISS | — |
| JAVA-053 | — | MISS | — |
| JAVA-054 | — | MISS | — |
| JAVA-055 | — | MISS | — |
| JAVA-056 | — | MISS | — |
| JAVA-057 | — | MISS | — |
| JAVA-058 | — | MISS | — |
| JAVA-059 | — | MISS | — |
| JAVA-060 | — | MISS | — |
| JAVA-061 | — | MISS | — |
| JAVA-062 | — | MISS | — |
| JAVA-063 | — | MISS | — |
| JAVA-064 | — | MISS | — |
| JAVA-065 | — | MISS | — |
| JAVA-066 | — | MISS | — |
| JAVA-067 | — | MISS | — |
| JAVA-068 | — | MISS | — |
| JAVA-069 | — | MISS | — |
| JAVA-070 | — | MISS | — |
| JAVA-071 | — | MISS | — |
| JAVA-072 | — | MISS | — |
| JAVA-073 | — | MISS | — |
| JAVA-074 | — | MISS | — |
| JAVA-075 | — | MISS | — |
| JAVA-076 | — | MISS | — |
| JAVA-077 | — | MISS | — |
| JAVA-078 | — | MISS | — |
| JAVA-079 | — | MISS | — |
| JAVA-080 | — | MISS | — |
| JAVA-081 | — | MISS | — |
| JAVA-082 | — | MISS | — |
| JAVA-083 | — | MISS | — |
| JAVA-084 | — | MISS | — |
| JAVA-085 | — | MISS | — |
| JAVA-086 | — | MISS | — |
| JAVA-087 | — | MISS | — |
| JAVA-088 | — | MISS | — |
| JAVA-089 | — | MISS | — |
| JAVA-090 | — | MISS | — |
| JAVA-091 | — | MISS | — |
| JAVA-092 | — | MISS | — |
| JAVA-093 | — | MISS | — |
| JAVA-094 | — | MISS | — |
| JAVA-095 | — | MISS | — |
| JAVA-096 | — | MISS | — |
| JAVA-097 | — | MISS | — |
| JAVA-098 | — | MISS | — |
| JAVA-099 | — | MISS | — |
| JAVA-100 | — | MISS | — |
| JAVA-101 | — | MISS | — |
| JAVA-102 | — | MISS | — |
| JAVA-103 | — | MISS | — |
| JAVA-104 | — | MISS | — |
| JAVA-105 | — | MISS | — |
| JAVA-106 | — | MISS | — |
| JAVA-107 | — | MISS | — |
| JAVA-108 | — | MISS | — |
| JAVA-109 | — | MISS | — |
| JAVA-110 | — | MISS | — |
| JAVA-111 | — | MISS | — |
| JAVA-112 | — | MISS | — |
| JAVA-113 | — | MISS | — |
| JAVA-114 | — | MISS | — |
| JAVA-115 | — | MISS | — |
| JAVA-116 | — | MISS | — |
| JAVA-117 | — | MISS | — |
| JAVA-118 | — | MISS | — |
| JAVA-119 | — | MISS | — |
| JAVA-120 | — | MISS | — |
| JAVA-121 | — | MISS | — |
| JAVA-122 | — | MISS | — |
| JAVA-123 | — | MISS | — |
| JAVA-124 | — | MISS | — |
| JAVA-125 | — | MISS | — |
| JAVA-126 | — | MISS | — |
| JAVA-127 | — | MISS | — |
| JAVA-128 | — | MISS | — |
| JAVA-129 | — | MISS | — |
| JAVA-130 | — | MISS | — |
| JAVA-131 | — | MISS | — |
| JAVA-132 | — | MISS | — |
| JAVA-133 | — | MISS | — |
| JAVA-134 | — | MISS | — |
| JAVA-135 | — | MISS | — |
| JAVA-136 | — | MISS | — |
| JAVA-137 | — | MISS | — |
| JAVA-138 | — | MISS | — |
| JAVA-139 | — | MISS | — |
| JAVA-140 | — | MISS | — |
| JAVA-141 | — | MISS | — |
| JAVA-142 | — | MISS | — |
| JAVA-143 | — | MISS | — |
| JAVA-144 | — | MISS | — |
| JAVA-145 | — | MISS | — |
| JAVA-146 | — | MISS | — |
| JAVA-147 | — | MISS | — |
| JAVA-148 | — | MISS | — |
| JAVA-149 | — | MISS | — |
| JAVA-150 | — | MISS | — |
| JAVA-151 | — | MISS | — |
| JAVA-152 | — | MISS | — |
| JAVA-153 | — | MISS | — |
| JAVA-154 | — | MISS | — |
| JAVA-155 | — | MISS | — |
| JAVA-156 | — | MISS | — |
| JAVA-157 | — | MISS | — |
| JAVA-158 | — | MISS | — |
| JAVA-159 | — | MISS | — |
| JAVA-160 | — | MISS | — |
| JAVA-161 | — | MISS | — |
| JAVA-162 | — | MISS | — |
| JAVA-163 | — | MISS | — |
| JAVA-164 | — | MISS | — |
| JAVA-165 | — | MISS | — |
| JAVA-166 | — | MISS | — |
| JAVA-167 | — | MISS | — |
| JAVA-168 | — | MISS | — |
| JAVA-169 | — | MISS | — |
| JAVA-170 | — | MISS | — |
| JAVA-171 | — | MISS | — |
| JAVA-172 | — | MISS | — |
| JAVA-173 | — | MISS | — |
| JAVA-174 | — | MISS | — |
| JAVA-175 | — | MISS | — |
| JAVA-176 | — | MISS | — |
| JAVA-177 | — | MISS | — |
| JAVA-178 | — | MISS | — |
| JAVA-179 | — | MISS | — |
| JAVA-180 | — | MISS | — |
| JAVA-181 | — | MISS | — |
| JAVA-182 | — | MISS | — |
| JAVA-183 | — | MISS | — |
| JAVA-184 | — | MISS | — |
| JAVA-185 | — | MISS | — |
| JAVA-186 | — | MISS | — |
| JAVA-187 | — | MISS | — |
| JAVA-188 | — | MISS | — |
| JAVA-189 | — | MISS | — |
| JAVA-190 | — | MISS | — |
| JAVA-191 | — | MISS | — |
| JAVA-192 | — | MISS | — |
| JAVA-193 | — | MISS | — |
| JAVA-194 | — | MISS | — |
| JAVA-195 | — | MISS | — |
| JAVA-196 | — | MISS | — |
| JAVA-197 | — | MISS | — |
| JAVA-198 | — | MISS | — |
| JAVA-199 | — | MISS | — |
| JAVA-200 | — | MISS | — |
| JAVA-201 | — | MISS | — |
| JAVA-202 | — | MISS | — |
| JAVA-203 | — | MISS | — |
| JAVA-204 | — | MISS | — |
| JAVA-205 | — | MISS | — |
| JAVA-206 | — | MISS | — |
| JAVA-207 | — | MISS | — |
| JAVA-208 | — | MISS | — |
| JAVA-209 | — | MISS | — |
| JAVA-210 | — | MISS | — |
| JAVA-211 | — | MISS | — |
| JAVA-212 | — | MISS | — |
| JAVA-213 | — | MISS | — |
| JAVA-214 | — | MISS | — |
| JAVA-215 | — | MISS | — |
| JAVA-216 | — | MISS | — |
| JAVA-217 | — | MISS | — |
| JAVA-218 | — | MISS | — |
| JAVA-219 | — | MISS | — |
| JAVA-220 | — | MISS | — |
| JAVA-221 | — | MISS | — |
| JAVA-222 | — | MISS | — |
| JAVA-223 | — | MISS | — |
| JAVA-224 | — | MISS | — |
| JAVA-225 | — | MISS | — |
| JAVA-226 | — | MISS | — |
| JAVA-227 | — | MISS | — |
| JAVA-228 | — | MISS | — |
| JAVA-229 | — | MISS | — |
| JAVA-230 | — | MISS | — |
| JAVA-231 | — | MISS | — |
| JAVA-232 | — | MISS | — |
| JAVA-233 | — | MISS | — |
| JAVA-234 | — | MISS | — |
| JAVA-235 | — | MISS | — |
| JAVA-236 | — | MISS | — |
| JAVA-237 | — | MISS | — |
| JAVA-238 | — | MISS | — |
| JAVA-239 | — | MISS | — |
| JAVA-240 | — | MISS | — |
| JAVA-241 | — | MISS | — |
| JAVA-242 | — | MISS | — |
| JAVA-243 | — | MISS | — |
| JAVA-244 | — | MISS | — |
| K8S-010 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| K8S-011 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| K8S-012 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| K8S-013 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| K8S-014 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| K8S-015 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| K8S-016 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| K8S-017 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| K8S-018 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| K8S-019 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| K8S-020 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| K8S-021 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| K8S-022 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| K8S-023 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| K8S-024 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| K8S-025 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| K8S-026 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| K8S-027 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| K8S-028 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| KFK-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| KFK-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| KFK-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| KFK-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| KFK-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| KFK-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| KFK-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| KFK-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| KFK-009 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| KFK-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| KFK-011 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| KFK-012 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| KFK-013 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| KFK-014 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| KFK-015 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| KFK-016 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| KFK-017 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| KFK-018 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| KFK-019 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| KFK-020 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| LGC-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| LGC-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| LGC-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| LGC-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| LGC-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| LGC-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| LGC-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| LGC-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| LGC-009 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| LGC-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| LIC-001 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| LIC-002 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| LIC-003 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| LIC-004 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| LIC-005 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| LIC-006 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| LIC-008 | `core/gold-standard-testbed/license_compliance_vulnerable.py` | HIT | Semgrep + marker |
| LIC-009 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| LIC-010 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| LIC-011 | `core/gold-standard-testbed/license_compliance_vulnerable.py` | HIT | Semgrep + marker |
| LOG-001 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Semgrep + marker |
| LOG-002 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| LOG-003 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| LOG-004 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| LOG-005 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| LOG-006 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| LOG-007 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Semgrep + marker |
| LOG-008 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| LOG-009 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Semgrep + marker |
| LOG-010 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| LOG-011 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| LOG-012 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| LOG-013 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| LOG-014 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| LOG-015 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| LOG-016 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| LOG-017 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| LOG-018 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| LOG-019 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| LOG-020 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| ML-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-009 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-011 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-012 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-013 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-014 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-015 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-016 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-017 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-018 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-019 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-020 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-021 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-022 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-023 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-024 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-025 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-026 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-027 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-028 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-029 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-030 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-031 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-032 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-033 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-034 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| ML-035 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| MOB-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-009 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| MOB-011 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-012 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-013 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-014 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-015 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-016 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-017 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-018 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-019 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-020 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-021 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| MOB-022 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-023 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-024 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-025 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-026 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-027 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-028 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-029 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-030 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-031 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-032 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-033 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-034 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-035 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-036 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-037 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-038 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-039 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MOB-040 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MSH-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| MSH-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MSH-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MSH-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MSH-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MSH-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MSH-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MSH-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MSH-009 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MSH-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MSH-011 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MSH-012 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MSH-013 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MSH-014 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| MSH-015 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| NGX-001 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NGX-002 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NGX-003 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NGX-004 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NGX-005 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| NGX-006 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NGX-007 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NGX-008 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NGX-009 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| NGX-010 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| NGX-011 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NGX-012 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NGX-013 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NJS-001 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| NJS-002 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NJS-003 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NJS-004 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NJS-005 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NJS-006 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NJS-007 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| NJS-008 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| NJS-009 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| NJS-010 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| NJS-011 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NJS-012 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NJS-013 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NJS-014 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NJS-015 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NJS-016 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| NJS-017 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NJS-018 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NJS-019 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NJS-020 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NJS-021 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NJS-022 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| NJS-023 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NJS-024 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NJS-025 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| NJS-026 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| NJS-027 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NJS-028 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NJS-029 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NJS-030 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NJS-031 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NJS-032 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NJS-033 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| NJS-034 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NJS-035 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NOS-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| NOS-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| NOS-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| NOS-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| NOS-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| NOS-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| NOS-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| NOS-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| NOS-009 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| NOS-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| NOS-011 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| NOS-012 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| NOS-013 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| NOS-014 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| NOS-015 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| NOS-016 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| NOS-017 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| NOS-018 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| NOS-019 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| NOS-020 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| NOV-CWE-1039 | — | MISS | — |
| NOV-CWE-1039-01 | — | MISS | — |
| NOV-CWE-117 | — | MISS | — |
| NOV-CWE-1333 | — | MISS | — |
| NOV-CWE-1333-01 | — | MISS | — |
| NOV-CWE-1333-02 | — | MISS | — |
| NOV-CWE-1336 | — | MISS | — |
| NOV-CWE-1336-01 | — | MISS | — |
| NOV-CWE-1426 | — | MISS | — |
| NOV-CWE-1427 | — | MISS | — |
| NOV-CWE-184 | — | MISS | — |
| NOV-CWE-184-01 | — | MISS | — |
| NOV-CWE-22 | — | MISS | — |
| NOV-CWE-22-01 | — | MISS | — |
| NOV-CWE-256 | — | MISS | — |
| NOV-CWE-295 | — | MISS | — |
| NOV-CWE-319 | — | MISS | — |
| NOV-CWE-330 | — | MISS | — |
| NOV-CWE-377 | — | MISS | — |
| NOV-CWE-489 | — | MISS | — |
| NOV-CWE-502 | — | MISS | — |
| NOV-CWE-502-01 | — | MISS | — |
| NOV-CWE-502-02 | — | MISS | — |
| NOV-CWE-532 | — | MISS | — |
| NOV-CWE-59 | — | MISS | — |
| NOV-CWE-611 | — | MISS | — |
| NOV-CWE-807 | — | MISS | — |
| NOV-CWE-807-01 | — | MISS | — |
| NOV-CWE-829 | — | MISS | — |
| NOV-CWE-829-01 | — | MISS | — |
| NOV-CWE-915 | — | MISS | — |
| NOV-CWE-918 | — | MISS | — |
| NOV-CWE-918-01 | — | MISS | — |
| NOV-CWE-918-02 | — | MISS | — |
| NOV-CWE-918-03 | — | MISS | — |
| NOV-CWE-94 | — | MISS | — |
| NOV-CWE-94-01 | — | MISS | — |
| NST-001 | `core/gold-standard-testbed/nestjs_vulnerable.ts` | HIT | Semgrep + marker |
| NST-002 | `core/gold-standard-testbed/nestjs_vulnerable.ts` | HIT | Semgrep + marker |
| NST-003 | `core/gold-standard-testbed/nestjs_vulnerable.ts` | HIT | Semgrep + marker |
| NST-004 | `core/gold-standard-testbed/nestjs_vulnerable.ts` | HIT | Semgrep + marker |
| NST-005 | `core/gold-standard-testbed/nestjs_vulnerable.ts` | HIT | Semgrep + marker |
| NST-006 | `core/gold-standard-testbed/nestjs_vulnerable.ts` | HIT | Semgrep + marker |
| NST-007 | `core/gold-standard-testbed/nestjs_vulnerable.ts` | HIT | Semgrep + marker |
| NST-008 | `core/gold-standard-testbed/nestjs_vulnerable.ts` | HIT | Semgrep + marker |
| NST-009 | `core/gold-standard-testbed/nestjs_vulnerable.ts` | HIT | Semgrep + marker |
| NST-010 | `core/gold-standard-testbed/nestjs_vulnerable.ts` | HIT | Semgrep + marker |
| NST-011 | `core/gold-standard-testbed/nestjs_vulnerable.ts` | HIT | Semgrep + marker |
| NST-012 | `core/gold-standard-testbed/nestjs_vulnerable.ts` | HIT | Semgrep + marker |
| NST-013 | `core/gold-standard-testbed/nestjs_vulnerable.ts` | HIT | Semgrep + marker |
| NST-014 | `core/gold-standard-testbed/nestjs_vulnerable.ts` | HIT | Semgrep + marker |
| NST-015 | `core/gold-standard-testbed/nestjs_vulnerable.ts` | HIT | Semgrep + marker |
| NST-016 | `core/gold-standard-testbed/nestjs_vulnerable.ts` | HIT | Semgrep + marker |
| NST-017 | `core/gold-standard-testbed/nestjs_vulnerable.ts` | HIT | Semgrep + marker |
| NST-018 | `core/gold-standard-testbed/nestjs_vulnerable.ts` | HIT | Semgrep + marker |
| NST-019 | `core/gold-standard-testbed/nestjs_vulnerable.ts` | HIT | Semgrep + marker |
| NST-020 | `core/gold-standard-testbed/nestjs_vulnerable.ts` | HIT | Semgrep + marker |
| NST-021 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NST-022 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NST-023 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| NST-024 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| NST-025 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| NST-026 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| NST-027 | — | MISS | — |
| NST-028 | — | MISS | — |
| NST-029 | — | MISS | — |
| NST-030 | — | MISS | — |
| NST-031 | — | MISS | — |
| NST-032 | — | MISS | — |
| NST-033 | — | MISS | — |
| NST-034 | — | MISS | — |
| NST-035 | — | MISS | — |
| NST-036 | — | MISS | — |
| NST-037 | — | MISS | — |
| NST-038 | — | MISS | — |
| NST-039 | — | MISS | — |
| NST-040 | — | MISS | — |
| NST-041 | — | MISS | — |
| NST-042 | — | MISS | — |
| NST-043 | — | MISS | — |
| NST-044 | — | MISS | — |
| NST-045 | — | MISS | — |
| NST-046 | — | MISS | — |
| NST-047 | — | MISS | — |
| NSX-101 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-102 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-103 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-104 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-105 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-106 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-107 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-108 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-109 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-110 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-111 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-112 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-113 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-114 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-115 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-116 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-117 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-118 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-119 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-120 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-121 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-122 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-123 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-124 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-125 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-126 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-127 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-128 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-129 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-130 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-131 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-132 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-133 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-134 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-135 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-136 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-137 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-138 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-139 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-140 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-141 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-142 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-143 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-144 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-145 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-146 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-147 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-148 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-149 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-150 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-151 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-152 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-153 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-154 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-155 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-156 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-157 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-158 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-159 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-160 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-161 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-162 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-163 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-164 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-165 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-166 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-167 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-168 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-169 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-170 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-171 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-172 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-173 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-174 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-175 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-176 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-177 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-178 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-179 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-180 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-181 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-182 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-183 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-184 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-185 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-186 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-187 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-188 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-189 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-190 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-191 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-192 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-193 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-194 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-195 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-196 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-197 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-198 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-199 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-200 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-201 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-202 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-203 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-204 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-205 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-206 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-207 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-208 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-209 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-210 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-211 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-212 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-213 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-214 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-215 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-216 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-217 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-218 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-219 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-220 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-221 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-222 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-223 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-224 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-225 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-226 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-227 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-228 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-229 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-230 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-231 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-232 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-233 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-234 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-235 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-236 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-237 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-238 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-239 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-240 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-241 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-242 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-243 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-244 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-245 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-246 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-247 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-248 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-249 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-250 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-251 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-252 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-253 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-254 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-255 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-256 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-257 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-258 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-259 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-260 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-261 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-262 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-263 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-264 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-265 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-266 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-267 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-268 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-269 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-270 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-271 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-272 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-273 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-274 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-275 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-276 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-277 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-278 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-279 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-280 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-281 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-282 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-283 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-284 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-285 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-286 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-287 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-288 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-289 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-290 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-291 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-292 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-293 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-294 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-295 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-296 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-297 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-298 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-299 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-300 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-301 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-302 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-303 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-304 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-305 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-306 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-307 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-308 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Semgrep + marker |
| NSX-309 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| NSX-310 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PHP-001 | — | MISS | — |
| PHP-002 | — | MISS | — |
| PHP-003 | — | MISS | — |
| PHP-004 | — | MISS | — |
| PHP-005 | — | MISS | — |
| PHP-006 | — | MISS | — |
| PHP-007 | — | MISS | — |
| PHP-008 | — | MISS | — |
| PHP-009 | — | MISS | — |
| PHP-010 | — | MISS | — |
| PHP-011 | — | MISS | — |
| PHP-012 | — | MISS | — |
| PHP-013 | — | MISS | — |
| PHP-014 | — | MISS | — |
| PHP-015 | — | MISS | — |
| PHP-016 | — | MISS | — |
| PHP-017 | — | MISS | — |
| PHP-018 | — | MISS | — |
| PHP-019 | — | MISS | — |
| PHP-020 | — | MISS | — |
| PHP-021 | — | MISS | — |
| PHP-022 | — | MISS | — |
| PHP-023 | — | MISS | — |
| PHP-024 | — | MISS | — |
| PHP-025 | — | MISS | — |
| PHP-026 | — | MISS | — |
| PHP-027 | — | MISS | — |
| PHP-028 | — | MISS | — |
| PHP-029 | — | MISS | — |
| PHP-030 | — | MISS | — |
| PHP-031 | — | MISS | — |
| PHP-032 | — | MISS | — |
| PHP-033 | — | MISS | — |
| PHP-034 | — | MISS | — |
| PHP-035 | — | MISS | — |
| PHP-036 | — | MISS | — |
| PHP-037 | — | MISS | — |
| PHP-038 | — | MISS | — |
| PHP-039 | — | MISS | — |
| PHP-040 | — | MISS | — |
| PHP-041 | — | MISS | — |
| PHP-042 | — | MISS | — |
| PHP-043 | — | MISS | — |
| PHP-044 | — | MISS | — |
| PHP-045 | — | MISS | — |
| PHPX-001 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-002 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-003 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-004 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-005 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-006 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-007 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-008 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-009 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-010 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-011 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-012 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-013 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-014 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-015 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-016 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-017 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-018 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-019 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-020 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-021 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-022 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-023 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-024 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-025 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-026 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-027 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-028 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-029 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-030 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-031 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-032 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-033 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-034 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-035 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-036 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-037 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-038 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-039 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-040 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-041 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-042 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-043 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-044 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-045 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-046 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-047 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-048 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-049 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-050 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-051 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-052 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-053 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-054 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-055 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-056 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-057 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-058 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-059 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-060 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-061 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-062 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-063 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-064 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-065 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-066 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-067 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-068 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-069 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-070 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-071 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-072 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-073 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-074 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-075 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-076 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-077 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-078 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-079 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-080 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-081 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-082 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-083 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-084 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-085 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-086 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-087 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-088 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-089 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-090 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-091 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-092 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-093 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-094 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-095 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-096 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-097 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-098 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-099 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-100 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-101 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-102 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-103 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-104 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-105 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-106 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-107 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-108 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-109 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-110 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-111 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-112 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-113 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-114 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-115 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-116 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-117 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-118 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-119 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-120 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-121 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-122 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-123 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-124 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-125 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-126 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-127 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-128 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-129 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-130 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-131 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-132 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-133 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-134 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-135 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-136 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-137 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-138 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-139 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-140 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-141 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-142 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-143 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-144 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-145 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-146 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-147 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-148 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-149 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-150 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-151 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-152 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-153 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-154 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-155 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-156 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-157 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-158 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-159 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-160 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-161 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-162 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-163 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-164 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-165 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-166 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-167 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-168 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-169 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-170 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-171 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-172 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-173 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-174 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-175 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-176 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-177 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-178 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-179 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-180 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-181 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-182 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-183 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-184 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-185 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-186 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-187 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-188 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-189 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-190 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-191 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-192 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-193 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-194 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-195 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-196 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-197 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-198 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-199 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PHPX-200 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| PLT-001 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| PLT-002 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| PLT-003 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| PLT-004 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| PLT-005 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| PLT-006 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| PLT-007 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| PLT-008 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| PLT-009 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| PLT-010 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| PLT-011 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| PLT-012 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| PLT-013 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| PLT-014 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| PLT-015 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| PLT-016 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| PY-001 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| PY-002 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| PY-003 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| PY-004 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| PY-005 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| PY-006 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| PY-007 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| PY-008 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| PY-009 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| PY-010 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| PY-011 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| PY-012 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| PY-013 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| PY-014 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| PY-015 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| PY-016 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| PY-017 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| PY-018 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| PY-019 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| PY-020 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| PY-021 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| PY-022 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| PY-023 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| PY-024 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| PY-025 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| PY-026 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| PY-027 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| PY-028 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| PY-029 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| PY-030 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| PY-100 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| PY-105 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| PY-110 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| PYX-201 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-202 | `core/gold-standard-testbed/django_mass_assignment.py` | HIT | Marker (testbed) |
| PYX-203 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-204 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-205 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-206 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-207 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-208 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-209 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-210 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-211 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-212 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-213 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-214 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-215 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-216 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-217 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-218 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-219 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-220 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-221 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-222 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-223 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-224 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-225 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-226 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-227 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-228 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-229 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-230 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-231 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-232 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-233 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-234 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-235 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-236 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-237 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-238 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-239 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-240 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-241 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-242 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-243 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-244 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-245 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-246 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-247 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-248 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-249 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-250 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-251 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-252 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-253 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-254 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-255 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-256 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-257 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-258 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-259 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-260 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-261 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-262 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-263 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-264 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-265 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-266 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-267 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-268 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-269 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-270 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-271 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-272 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-273 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-274 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-275 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-276 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-277 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-278 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-279 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-280 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-281 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-282 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-283 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-284 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-285 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-286 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-287 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-288 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-289 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-290 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-291 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-292 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-293 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-294 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-295 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-296 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-297 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-298 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-299 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-300 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-301 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-302 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-303 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-304 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-305 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-306 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-307 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-308 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-309 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-310 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-311 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-312 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-313 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-314 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-315 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-316 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-317 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-318 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-319 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-320 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-321 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-322 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-323 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-324 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-325 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-326 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-327 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-328 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-329 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-330 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-331 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-332 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-333 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-334 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-335 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-336 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-337 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-338 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-339 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-340 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-341 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-342 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-343 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-344 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-345 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-346 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-347 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-348 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-349 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-350 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-351 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-352 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-353 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-354 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-355 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-356 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-357 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-358 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-359 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-360 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-361 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-362 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-363 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-364 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-365 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-366 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-367 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-368 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-369 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-370 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-371 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-372 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-373 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-374 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-375 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-376 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-377 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-378 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-379 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-380 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-381 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-382 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-383 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-384 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-385 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-386 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-387 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-388 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-389 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-390 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-391 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-392 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-393 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-394 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-395 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-396 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-397 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-398 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-399 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-400 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-401 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-402 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-403 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-404 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-405 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-406 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-407 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-408 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-409 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-410 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-411 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-412 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-413 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-414 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-415 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-416 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-417 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-418 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-419 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| PYX-420 | `core/gold-standard-testbed/multistack_surge_validation.py` | HIT | Marker (testbed) |
| RAC-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RAC-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RAC-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RAC-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RAC-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RAC-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RAC-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RAC-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RAC-009 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RAC-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RAC-011 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RAC-012 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RAC-013 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RAC-014 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RAC-015 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RED-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| RED-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RED-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RED-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RED-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RED-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RED-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RED-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RED-009 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RED-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RED-011 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RED-012 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RED-013 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RED-014 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RED-015 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RLP-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RLP-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RLP-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RLP-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RLP-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RLP-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RLP-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RLP-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RLP-009 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RLP-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RMG-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RMG-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RMG-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RMG-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RMG-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RMG-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| RMG-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RMG-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RMG-009 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RMG-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RMG-011 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RMG-012 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RMG-013 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RMG-014 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RMG-015 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RMG-016 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RMG-017 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RMG-018 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RMG-019 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RMG-020 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RMG-021 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RMG-022 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RMG-023 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RMG-024 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RMG-025 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RMG-026 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RMG-027 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RMG-028 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RMG-029 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RMG-030 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| RRC-001 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RRC-002 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RRC-003 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RRC-004 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RRC-005 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RRC-006 | `core/gold-standard-testbed/ru_regulatory_vulnerable.py` | HIT | Semgrep + marker |
| RRC-007 | `core/gold-standard-testbed/ru_regulatory_vulnerable.py` | HIT | Semgrep + marker |
| RRC-008 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RRC-009 | `core/gold-standard-testbed/ru_regulatory_vulnerable.py` | HIT | Semgrep + marker |
| RRC-010 | `core/gold-standard-testbed/ru_regulatory_vulnerable.py` | HIT | Semgrep + marker |
| RRC-011 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RRC-012 | `core/gold-standard-testbed/ru_regulatory_vulnerable.py` | HIT | Semgrep + marker |
| RRC-013 | `core/gold-standard-testbed/integration_security_vulnerable.py` | HIT | Marker (testbed) |
| RRC-014 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RRC-015 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RRC-016 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RRC-017 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RRC-018 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RRC-019 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RRC-020 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RRC-021 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RRC-022 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RRC-023 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RRC-024 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RRC-025 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RRC-026 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| RSX-001 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RSX-002 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-003 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-004 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-005 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-006 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RSX-007 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-008 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-009 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-010 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-011 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RSX-012 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-013 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-014 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-015 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-016 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RSX-017 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-018 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-019 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-020 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-021 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RSX-022 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-023 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-024 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-025 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-026 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RSX-027 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-028 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-029 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-030 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-031 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RSX-032 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-033 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-034 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-035 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-036 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RSX-037 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-038 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-039 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-040 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-041 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RSX-042 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-043 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-044 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-045 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-046 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RSX-047 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-048 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-049 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-050 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-051 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RSX-052 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-053 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-054 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-055 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-056 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RSX-057 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-058 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-059 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-060 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-061 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RSX-062 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-063 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-064 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-065 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-066 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RSX-067 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-068 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-069 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-070 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-071 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RSX-072 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-073 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-074 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-075 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-076 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RSX-077 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-078 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-079 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-080 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-081 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RSX-082 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-083 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-084 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-085 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-086 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RSX-087 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-088 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-089 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-090 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-091 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RSX-092 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-093 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-094 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-095 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-096 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RSX-097 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-098 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-099 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-100 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-101 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RSX-102 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-103 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-104 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-105 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-106 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RSX-107 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-108 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-109 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-110 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-111 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RSX-112 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-113 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-114 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-115 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-116 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RSX-117 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-118 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-119 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-120 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-121 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RSX-122 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-123 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-124 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-125 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-126 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RSX-127 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-128 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-129 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-130 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-131 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RSX-132 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-133 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-134 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-135 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-136 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RSX-137 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-138 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-139 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-140 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-141 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RSX-142 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-143 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-144 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-145 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-146 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RSX-147 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-148 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-149 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RSX-150 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUB-001 | — | MISS | — |
| RUB-002 | — | MISS | — |
| RUB-003 | — | MISS | — |
| RUB-004 | — | MISS | — |
| RUB-005 | — | MISS | — |
| RUB-006 | — | MISS | — |
| RUB-007 | — | MISS | — |
| RUB-008 | — | MISS | — |
| RUB-009 | — | MISS | — |
| RUB-010 | — | MISS | — |
| RUB-011 | — | MISS | — |
| RUB-012 | — | MISS | — |
| RUB-013 | — | MISS | — |
| RUB-014 | — | MISS | — |
| RUB-015 | — | MISS | — |
| RUB-016 | — | MISS | — |
| RUB-017 | — | MISS | — |
| RUB-018 | — | MISS | — |
| RUB-019 | — | MISS | — |
| RUB-020 | — | MISS | — |
| RUB-021 | — | MISS | — |
| RUB-022 | — | MISS | — |
| RUB-023 | — | MISS | — |
| RUB-024 | — | MISS | — |
| RUB-025 | — | MISS | — |
| RUB-026 | — | MISS | — |
| RUB-027 | — | MISS | — |
| RUB-028 | — | MISS | — |
| RUB-029 | — | MISS | — |
| RUB-030 | — | MISS | — |
| RUB-031 | — | MISS | — |
| RUB-032 | — | MISS | — |
| RUB-033 | — | MISS | — |
| RUB-034 | — | MISS | — |
| RUB-035 | — | MISS | — |
| RUB-036 | — | MISS | — |
| RUB-037 | — | MISS | — |
| RUB-038 | — | MISS | — |
| RUB-039 | — | MISS | — |
| RUB-040 | — | MISS | — |
| RUB-041 | — | MISS | — |
| RUB-042 | — | MISS | — |
| RUB-043 | — | MISS | — |
| RUB-044 | — | MISS | — |
| RUB-045 | — | MISS | — |
| RUB-046 | — | MISS | — |
| RUB-047 | — | MISS | — |
| RUB-048 | — | MISS | — |
| RUB-049 | — | MISS | — |
| RUB-050 | — | MISS | — |
| RUB-051 | — | MISS | — |
| RUB-052 | — | MISS | — |
| RUB-053 | — | MISS | — |
| RUB-054 | — | MISS | — |
| RUB-055 | — | MISS | — |
| RUB-056 | — | MISS | — |
| RUB-057 | — | MISS | — |
| RUB-058 | — | MISS | — |
| RUB-059 | — | MISS | — |
| RUB-060 | — | MISS | — |
| RUB-061 | — | MISS | — |
| RUB-062 | — | MISS | — |
| RUB-063 | — | MISS | — |
| RUB-064 | — | MISS | — |
| RUB-065 | — | MISS | — |
| RUBY-001 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RUBY-002 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RUBY-003 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RUBY-004 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RUBY-005 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RUBY-006 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RUBY-007 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RUBY-008 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RUBY-009 | `core/gold-standard-testbed/multi_lang_vulnerable/ruby_vulnerable.rb` | HIT | Semgrep + marker |
| RUBY-010 | `core/gold-standard-testbed/multi_lang_vulnerable/ruby_vulnerable.rb` | HIT | Semgrep + marker |
| RUBY-011 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RUBY-012 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RUBY-013 | `core/gold-standard-testbed/multi_lang_vulnerable/ruby_vulnerable.rb` | HIT | Semgrep + marker |
| RUBY-014 | `core/gold-standard-testbed/multi_lang_vulnerable/ruby_vulnerable.rb` | HIT | Semgrep + marker |
| RUBY-015 | `core/gold-standard-testbed/multi_lang_vulnerable/ruby_vulnerable.rb` | HIT | Semgrep + marker |
| RUBY-016 | `core/gold-standard-testbed/multi_lang_vulnerable/ruby_vulnerable.rb` | HIT | Semgrep + marker |
| RUBY-017 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RUBY-018 | `core/gold-standard-testbed/multi_lang_vulnerable/ruby_vulnerable.rb` | HIT | Semgrep + marker |
| RUBY-019 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| RUBY-020 | `core/gold-standard-testbed/multi_lang_vulnerable/ruby_vulnerable.rb` | HIT | Semgrep + marker |
| RUBYX-021 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-022 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-023 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-024 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-025 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-026 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-027 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-028 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-029 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-030 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-031 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-032 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-033 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-034 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-035 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-036 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-037 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-038 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-039 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-040 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-041 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-042 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-043 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-044 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-045 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-046 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-047 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-048 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-049 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-050 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-051 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-052 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-053 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-054 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-055 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-056 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-057 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-058 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-059 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-060 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-061 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-062 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-063 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-064 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-065 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-066 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-067 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-068 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-069 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-070 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-071 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-072 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-073 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-074 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-075 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-076 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-077 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-078 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-079 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-080 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-081 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-082 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-083 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-084 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-085 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-086 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-087 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-088 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-089 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-090 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-091 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-092 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-093 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-094 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-095 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-096 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-097 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-098 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-099 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-100 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-101 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-102 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-103 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-104 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-105 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-106 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-107 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-108 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-109 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-110 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-111 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-112 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-113 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-114 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-115 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-116 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-117 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-118 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-119 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-120 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-121 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-122 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-123 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-124 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-125 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-126 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-127 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-128 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-129 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-130 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-131 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-132 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-133 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-134 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-135 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-136 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-137 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-138 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-139 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-140 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-141 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-142 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-143 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-144 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-145 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-146 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-147 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-148 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-149 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-150 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-151 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-152 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-153 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-154 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-155 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-156 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-157 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-158 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-159 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-160 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-161 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-162 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-163 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-164 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-165 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-166 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-167 | `core/gold-standard-testbed/final500_validation.py` | HIT | Semgrep + marker |
| RUBYX-168 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-169 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| RUBYX-170 | `core/gold-standard-testbed/final500_validation.py` | HIT | Marker (testbed) |
| SC-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SC-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SC-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SC-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SC-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SC-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SC-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SC-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SC-009 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SC-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SC-011 | `core/gold-standard-testbed/custom_unsafe_serializer.java` | HIT | Marker (testbed) |
| SC-012 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SC-013 | `core/gold-standard-testbed/custom_unsafe_serializer.java` | HIT | Marker (testbed) |
| SC-014 | `core/gold-standard-testbed/custom_unsafe_serializer.java` | HIT | Marker (testbed) |
| SC-015 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SC-016 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SC-017 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SC-018 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SC-019 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SC-020 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SC-021 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SC-022 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SC-023 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SC-024 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SC-025 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SDK-001 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-002 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-003 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-004 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-005 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-006 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-007 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-008 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-009 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-010 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-011 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-012 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-013 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-014 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-015 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-016 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-017 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-018 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-019 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-020 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-021 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-022 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-023 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-024 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-025 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-026 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-027 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-028 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-029 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-030 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-031 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-032 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-033 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-034 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-035 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-036 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-037 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-038 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-039 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-040 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-041 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-042 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-043 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-044 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-045 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-046 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-047 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-048 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-049 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-050 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-051 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-052 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-053 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-054 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-055 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-056 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-057 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-058 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-059 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-060 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-061 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-062 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-063 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-064 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-065 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-066 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-067 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-068 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-069 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-070 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-071 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-072 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-073 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-074 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-075 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-076 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-077 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-078 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-079 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-080 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-081 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-082 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-083 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-084 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-085 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-086 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-087 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-088 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-089 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-090 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-091 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-092 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-093 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-094 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-095 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-096 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-097 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-098 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-099 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SDK-100 | `core/gold-standard-testbed/final4000_validation.py` | HIT | Marker (testbed) |
| SEC-001 | `core/gold-standard-testbed/cloud_secrets_vulnerable.py` | HIT | Semgrep + marker |
| SEC-002 | `core/gold-standard-testbed/cloud_secrets_vulnerable.yaml` | HIT | Marker (testbed) |
| SEC-003 | `core/gold-standard-testbed/cloud_secrets_vulnerable.yaml` | HIT | Semgrep + marker |
| SEC-004 | `core/gold-standard-testbed/cloud_secrets_vulnerable.yaml` | HIT | Semgrep + marker |
| SEC-005 | `core/gold-standard-testbed/cloud_secrets_vulnerable.yaml` | HIT | Semgrep + marker |
| SEC-006 | `core/gold-standard-testbed/cloud_secrets_vulnerable.py` | HIT | Semgrep + marker |
| SEC-007 | `core/gold-standard-testbed/cloud_secrets_vulnerable.py` | HIT | Semgrep + marker |
| SEC-008 | `core/gold-standard-testbed/cloud_secrets_vulnerable.py` | HIT | Semgrep + marker |
| SEC-009 | `core/gold-standard-testbed/cloud_secrets_vulnerable.py` | HIT | Semgrep + marker |
| SEC-010 | `core/gold-standard-testbed/cloud_secrets_vulnerable.py` | HIT | Semgrep + marker |
| SEC-011 | `core/gold-standard-testbed/cloud_secrets_vulnerable.py` | HIT | Semgrep + marker |
| SEC-012 | `core/gold-standard-testbed/cloud_secrets_vulnerable.yaml` | HIT | Marker (testbed) |
| SEC-013 | `core/gold-standard-testbed/cloud_secrets_vulnerable.py` | HIT | Marker (testbed) |
| SEC-014 | `core/gold-standard-testbed/cloud_secrets_vulnerable.py` | HIT | Semgrep + marker |
| SEC-015 | `core/gold-standard-testbed/cloud_secrets_vulnerable.py` | HIT | Marker (testbed) |
| SEC-016 | `core/gold-standard-testbed/cloud_secrets_vulnerable.yaml` | HIT | Marker (testbed) |
| SEC-017 | `core/gold-standard-testbed/cloud_secrets_vulnerable.yaml` | HIT | Semgrep + marker |
| SEC-GL-001 | — | MISS | — |
| SEC-GL-002 | — | MISS | — |
| SEC-GL-003 | — | MISS | — |
| SEC-GL-004 | — | MISS | — |
| SEC-GL-005 | — | MISS | — |
| SEC-GL-006 | — | MISS | — |
| SEC-GL-007 | — | MISS | — |
| SEC-GL-008 | — | MISS | — |
| SEC-GL-009 | — | MISS | — |
| SEC-GL-010 | — | MISS | — |
| SEC-GL-011 | — | MISS | — |
| SEC-GL-012 | — | MISS | — |
| SEC-GL-013 | — | MISS | — |
| SEC-GL-014 | — | MISS | — |
| SEC-GL-015 | — | MISS | — |
| SEC-GL-016 | — | MISS | — |
| SEC-GL-017 | — | MISS | — |
| SEC-GL-018 | — | MISS | — |
| SEC-GL-019 | — | MISS | — |
| SEC-GL-020 | — | MISS | — |
| SEC-GL-021 | — | MISS | — |
| SEC-GL-022 | — | MISS | — |
| SEC-GL-023 | — | MISS | — |
| SEC-GL-024 | — | MISS | — |
| SEC-GL-025 | — | MISS | — |
| SEC-GL-026 | — | MISS | — |
| SEC-GL-027 | — | MISS | — |
| SEC-GL-028 | — | MISS | — |
| SEC-GL-029 | — | MISS | — |
| SEC-GL-030 | — | MISS | — |
| SEC-GL-031 | — | MISS | — |
| SEC-GL-032 | — | MISS | — |
| SEC-GL-033 | — | MISS | — |
| SEC-GL-034 | — | MISS | — |
| SEC-GL-035 | — | MISS | — |
| SEC-GL-036 | — | MISS | — |
| SEC-GL-037 | — | MISS | — |
| SEC-GL-038 | — | MISS | — |
| SEC-GL-039 | — | MISS | — |
| SEC-GL-040 | — | MISS | — |
| SEC-GL-041 | — | MISS | — |
| SEC-GL-042 | — | MISS | — |
| SEC-GL-043 | — | MISS | — |
| SEC-GL-044 | — | MISS | — |
| SEC-GL-045 | — | MISS | — |
| SEC-GL-046 | — | MISS | — |
| SEC-GL-047 | — | MISS | — |
| SEC-GL-048 | — | MISS | — |
| SEC-GL-049 | — | MISS | — |
| SEC-GL-050 | — | MISS | — |
| SEC-GL-051 | — | MISS | — |
| SEC-GL-052 | — | MISS | — |
| SEC-GL-053 | — | MISS | — |
| SEC-GL-054 | — | MISS | — |
| SEC-GL-055 | — | MISS | — |
| SEC-GL-056 | — | MISS | — |
| SEC-GL-057 | — | MISS | — |
| SEC-GL-058 | — | MISS | — |
| SEC-GL-059 | — | MISS | — |
| SEC-GL-060 | — | MISS | — |
| SEC-GL-061 | — | MISS | — |
| SEC-GL-062 | — | MISS | — |
| SEC-GL-063 | — | MISS | — |
| SEC-GL-064 | — | MISS | — |
| SEC-GL-065 | — | MISS | — |
| SEC-GL-066 | — | MISS | — |
| SEC-GL-067 | — | MISS | — |
| SEC-GL-068 | — | MISS | — |
| SEC-GL-069 | — | MISS | — |
| SEC-GL-070 | — | MISS | — |
| SEC-GL-071 | — | MISS | — |
| SEC-GL-072 | — | MISS | — |
| SEC-GL-073 | — | MISS | — |
| SEC-GL-074 | — | MISS | — |
| SEC-GL-075 | — | MISS | — |
| SEC-GL-076 | — | MISS | — |
| SEC-GL-077 | — | MISS | — |
| SEC-GL-078 | — | MISS | — |
| SEC-GL-079 | — | MISS | — |
| SEC-GL-080 | — | MISS | — |
| SEC-GL-081 | — | MISS | — |
| SEC-GL-082 | — | MISS | — |
| SEC-GL-083 | — | MISS | — |
| SEC-GL-084 | — | MISS | — |
| SEC-GL-085 | — | MISS | — |
| SEC-GL-086 | — | MISS | — |
| SEC-GL-087 | — | MISS | — |
| SEC-GL-088 | — | MISS | — |
| SEC-GL-089 | — | MISS | — |
| SEC-GL-090 | — | MISS | — |
| SEC-GL-091 | — | MISS | — |
| SEC-GL-092 | — | MISS | — |
| SEC-GL-093 | — | MISS | — |
| SEC-GL-094 | — | MISS | — |
| SEC-GL-095 | — | MISS | — |
| SEC-GL-096 | — | MISS | — |
| SEC-GL-097 | — | MISS | — |
| SEC-GL-098 | — | MISS | — |
| SEC-GL-099 | — | MISS | — |
| SEC-GL-100 | — | MISS | — |
| SEC-GL-101 | — | MISS | — |
| SEC-GL-102 | — | MISS | — |
| SEC-GL-103 | — | MISS | — |
| SEC-GL-104 | — | MISS | — |
| SEC-GL-105 | — | MISS | — |
| SEC-GL-106 | — | MISS | — |
| SEC-GL-107 | — | MISS | — |
| SEC-GL-108 | — | MISS | — |
| SEC-GL-109 | — | MISS | — |
| SEC-GL-110 | — | MISS | — |
| SEC-GL-111 | — | MISS | — |
| SEC-GL-112 | — | MISS | — |
| SEC-GL-113 | — | MISS | — |
| SEC-GL-114 | — | MISS | — |
| SEC-GL-115 | — | MISS | — |
| SEC-GL-116 | — | MISS | — |
| SEC-GL-117 | — | MISS | — |
| SEC-GL-118 | — | MISS | — |
| SEC-GL-119 | — | MISS | — |
| SEC-GL-120 | — | MISS | — |
| SEC-GL-121 | — | MISS | — |
| SEC-GL-122 | — | MISS | — |
| SEC-GL-123 | — | MISS | — |
| SEC-GL-124 | — | MISS | — |
| SEC-GL-125 | — | MISS | — |
| SEC-GL-126 | — | MISS | — |
| SEC-GL-127 | — | MISS | — |
| SEC-GL-128 | — | MISS | — |
| SEC-GL-129 | — | MISS | — |
| SEC-GL-130 | — | MISS | — |
| SEC-GL-131 | — | MISS | — |
| SEC-GL-132 | — | MISS | — |
| SEC-GL-133 | — | MISS | — |
| SEC-GL-134 | — | MISS | — |
| SEC-GL-135 | — | MISS | — |
| SEC-GL-136 | — | MISS | — |
| SEC-GL-137 | — | MISS | — |
| SEC-GL-138 | — | MISS | — |
| SEC-GL-139 | — | MISS | — |
| SEC-GL-140 | — | MISS | — |
| SEC-GL-141 | — | MISS | — |
| SEC-GL-142 | — | MISS | — |
| SEC-GL-143 | — | MISS | — |
| SEC-GL-144 | — | MISS | — |
| SEC-GL-145 | — | MISS | — |
| SEC-GL-146 | — | MISS | — |
| SEC-GL-147 | — | MISS | — |
| SEC-GL-148 | — | MISS | — |
| SEC-GL-149 | — | MISS | — |
| SEC-GL-150 | — | MISS | — |
| SEC-GL-151 | — | MISS | — |
| SEC-GL-152 | — | MISS | — |
| SEC-GL-153 | — | MISS | — |
| SEC-GL-154 | — | MISS | — |
| SEC-GL-155 | — | MISS | — |
| SEC-GL-156 | — | MISS | — |
| SEC-GL-158 | — | MISS | — |
| SEC-GL-159 | — | MISS | — |
| SEC-GL-160 | — | MISS | — |
| SEC-GL-161 | — | MISS | — |
| SEC-GL-162 | — | MISS | — |
| SEC-GL-163 | — | MISS | — |
| SEC-GL-164 | — | MISS | — |
| SEC-GL-165 | — | MISS | — |
| SEC-GL-166 | — | MISS | — |
| SEC-GL-167 | — | MISS | — |
| SEC-GL-168 | — | MISS | — |
| SEC-GL-169 | — | MISS | — |
| SEC-GL-170 | — | MISS | — |
| SEC-GL-171 | — | MISS | — |
| SEC-GL-172 | — | MISS | — |
| SEC-GL-173 | — | MISS | — |
| SEC-GL-174 | — | MISS | — |
| SEC-GL-175 | — | MISS | — |
| SEC-GL-176 | — | MISS | — |
| SEC-GL-177 | — | MISS | — |
| SEC-GL-178 | — | MISS | — |
| SEC-GL-179 | — | MISS | — |
| SEC-GL-180 | — | MISS | — |
| SEC-GL-181 | — | MISS | — |
| SEC-GL-182 | — | MISS | — |
| SEC-GL-183 | — | MISS | — |
| SEC-GL-184 | — | MISS | — |
| SEC-GL-185 | — | MISS | — |
| SEC-GL-186 | — | MISS | — |
| SEC-GL-187 | — | MISS | — |
| SEC-GL-188 | — | MISS | — |
| SEC-GL-189 | — | MISS | — |
| SEC-GL-190 | — | MISS | — |
| SEC-GL-191 | — | MISS | — |
| SEC-GL-192 | — | MISS | — |
| SEC-GL-193 | — | MISS | — |
| SEC-GL-194 | — | MISS | — |
| SEC-GL-195 | — | MISS | — |
| SEC-GL-196 | — | MISS | — |
| SEC-GL-197 | — | MISS | — |
| SEC-GL-198 | — | MISS | — |
| SEC-GL-199 | — | MISS | — |
| SEC-GL-200 | — | MISS | — |
| SEC-GL-201 | — | MISS | — |
| SEC-GL-202 | — | MISS | — |
| SEC-GL-203 | — | MISS | — |
| SEC-GL-204 | — | MISS | — |
| SEC-GL-205 | — | MISS | — |
| SEC-GL-206 | — | MISS | — |
| SEC-GL-207 | — | MISS | — |
| SEC-GL-208 | — | MISS | — |
| SEC-GL-209 | — | MISS | — |
| SEC-GL-210 | — | MISS | — |
| SEC-GL-211 | — | MISS | — |
| SEC-GL-212 | — | MISS | — |
| SEC-GL-213 | — | MISS | — |
| SEC-GL-214 | — | MISS | — |
| SEC-GL-215 | — | MISS | — |
| SEC-GL-216 | — | MISS | — |
| SEC-GL-217 | — | MISS | — |
| SEC-GL-218 | — | MISS | — |
| SEC-GL-219 | — | MISS | — |
| SEC-GL-220 | — | MISS | — |
| SEC-GL-221 | — | MISS | — |
| SEC-GL-222 | — | MISS | — |
| SEC-TH-001 | — | MISS | — |
| SEC-TH-002 | — | MISS | — |
| SEC-TH-003 | — | MISS | — |
| SEC-TH-004 | — | MISS | — |
| SEC-TH-005 | — | MISS | — |
| SEC-TH-006 | — | MISS | — |
| SEC-TH-007 | — | MISS | — |
| SEC-TH-008 | — | MISS | — |
| SEC-TH-009 | — | MISS | — |
| SEC-TH-010 | — | MISS | — |
| SEC-TH-011 | — | MISS | — |
| SEC-TH-012 | — | MISS | — |
| SEC-TH-013 | — | MISS | — |
| SEC-TH-014 | — | MISS | — |
| SEC-TH-015 | — | MISS | — |
| SEC-TH-016 | — | MISS | — |
| SEC-TH-017 | — | MISS | — |
| SEC-TH-018 | — | MISS | — |
| SEC-TH-019 | — | MISS | — |
| SEC-TH-020 | — | MISS | — |
| SEC-TH-021 | — | MISS | — |
| SEC-TH-022 | — | MISS | — |
| SEC-TH-023 | — | MISS | — |
| SEC-TH-024 | — | MISS | — |
| SEC-TH-025 | — | MISS | — |
| SEC-TH-026 | — | MISS | — |
| SEC-TH-027 | — | MISS | — |
| SEC-TH-028 | — | MISS | — |
| SEC-TH-029 | — | MISS | — |
| SEC-TH-030 | — | MISS | — |
| SEC-TH-031 | — | MISS | — |
| SEC-TH-032 | — | MISS | — |
| SEC-TH-033 | — | MISS | — |
| SEC-TH-034 | — | MISS | — |
| SEC-TH-035 | — | MISS | — |
| SEC-TH-036 | — | MISS | — |
| SEC-TH-037 | — | MISS | — |
| SEC-TH-038 | — | MISS | — |
| SEC-TH-039 | — | MISS | — |
| SEC-TH-040 | — | MISS | — |
| SEC-TH-041 | — | MISS | — |
| SEC-TH-042 | — | MISS | — |
| SEC-TH-043 | — | MISS | — |
| SEC-TH-044 | — | MISS | — |
| SEC-TH-045 | — | MISS | — |
| SEC-TH-046 | — | MISS | — |
| SEC-TH-047 | — | MISS | — |
| SEC-TH-049 | — | MISS | — |
| SEC-TH-050 | — | MISS | — |
| SEC-TH-051 | — | MISS | — |
| SEC-TH-052 | — | MISS | — |
| SEC-TH-053 | — | MISS | — |
| SEC-TH-054 | — | MISS | — |
| SEC-TH-055 | — | MISS | — |
| SEC-TH-056 | — | MISS | — |
| SEC-TH-057 | — | MISS | — |
| SEC-TH-058 | — | MISS | — |
| SEC-TH-059 | — | MISS | — |
| SEC-TH-060 | — | MISS | — |
| SEC-TH-061 | — | MISS | — |
| SEC-TH-062 | — | MISS | — |
| SEC-TH-063 | — | MISS | — |
| SEC-TH-064 | — | MISS | — |
| SEC-TH-065 | — | MISS | — |
| SEC-TH-066 | — | MISS | — |
| SEC-TH-067 | — | MISS | — |
| SEC-TH-068 | — | MISS | — |
| SEC-TH-069 | — | MISS | — |
| SEC-TH-070 | — | MISS | — |
| SEC-TH-071 | — | MISS | — |
| SEC-TH-072 | — | MISS | — |
| SEC-TH-073 | — | MISS | — |
| SEC-TH-074 | — | MISS | — |
| SEC-TH-075 | — | MISS | — |
| SEC-TH-076 | — | MISS | — |
| SEC-TH-077 | — | MISS | — |
| SEC-TH-078 | — | MISS | — |
| SEC-TH-079 | — | MISS | — |
| SEC-TH-080 | — | MISS | — |
| SEC-TH-081 | — | MISS | — |
| SEC-TH-082 | — | MISS | — |
| SEC-TH-083 | — | MISS | — |
| SEC-TH-084 | — | MISS | — |
| SEC-TH-085 | — | MISS | — |
| SEC-TH-086 | — | MISS | — |
| SEC-TH-087 | — | MISS | — |
| SEC-TH-088 | — | MISS | — |
| SEC-TH-089 | — | MISS | — |
| SEC-TH-090 | — | MISS | — |
| SEC-TH-091 | — | MISS | — |
| SEC-TH-092 | — | MISS | — |
| SEC-TH-093 | — | MISS | — |
| SEC-TH-094 | — | MISS | — |
| SEC-TH-095 | — | MISS | — |
| SEC-TH-096 | — | MISS | — |
| SEC-TH-097 | — | MISS | — |
| SEC-TH-098 | — | MISS | — |
| SEC-TH-099 | — | MISS | — |
| SEC-TH-100 | — | MISS | — |
| SEC-TH-101 | — | MISS | — |
| SEC-TH-102 | — | MISS | — |
| SEC-TH-103 | — | MISS | — |
| SEC-TH-104 | — | MISS | — |
| SEC-TH-105 | — | MISS | — |
| SEC-TH-106 | — | MISS | — |
| SEC-TH-107 | — | MISS | — |
| SEC-TH-108 | — | MISS | — |
| SEC-TH-109 | — | MISS | — |
| SEC-TH-110 | — | MISS | — |
| SEC-TH-111 | — | MISS | — |
| SEC-TH-112 | — | MISS | — |
| SEC-TH-113 | — | MISS | — |
| SEC-TH-114 | — | MISS | — |
| SEC-TH-115 | — | MISS | — |
| SEC-TH-116 | — | MISS | — |
| SEC-TH-117 | — | MISS | — |
| SEC-TH-118 | — | MISS | — |
| SEC-TH-119 | — | MISS | — |
| SEC-TH-120 | — | MISS | — |
| SEC-TH-121 | — | MISS | — |
| SEC-TH-122 | — | MISS | — |
| SEC-TH-123 | — | MISS | — |
| SEC-TH-124 | — | MISS | — |
| SEC-TH-125 | — | MISS | — |
| SEC-TH-126 | — | MISS | — |
| SEC-TH-127 | — | MISS | — |
| SEC-TH-128 | — | MISS | — |
| SEC-TH-129 | — | MISS | — |
| SEC-TH-130 | — | MISS | — |
| SEC-TH-131 | — | MISS | — |
| SEC-TH-132 | — | MISS | — |
| SEC-TH-133 | — | MISS | — |
| SEC-TH-134 | — | MISS | — |
| SEC-TH-135 | — | MISS | — |
| SEC-TH-136 | — | MISS | — |
| SEC-TH-137 | — | MISS | — |
| SEC-TH-138 | — | MISS | — |
| SEC-TH-139 | — | MISS | — |
| SEC-TH-140 | — | MISS | — |
| SEC-TH-141 | — | MISS | — |
| SEC-TH-142 | — | MISS | — |
| SEC-TH-143 | — | MISS | — |
| SEC-TH-144 | — | MISS | — |
| SEC-TH-145 | — | MISS | — |
| SEC-TH-146 | — | MISS | — |
| SEC-TH-147 | — | MISS | — |
| SEC-TH-148 | — | MISS | — |
| SEC-TH-149 | — | MISS | — |
| SEC-TH-150 | — | MISS | — |
| SEC-TH-151 | — | MISS | — |
| SEC-TH-152 | — | MISS | — |
| SEC-TH-153 | — | MISS | — |
| SEC-TH-154 | — | MISS | — |
| SEC-TH-155 | — | MISS | — |
| SEC-TH-156 | — | MISS | — |
| SEC-TH-157 | — | MISS | — |
| SEC-TH-158 | — | MISS | — |
| SEC-TH-159 | — | MISS | — |
| SEC-TH-160 | — | MISS | — |
| SEC-TH-161 | — | MISS | — |
| SEC-TH-162 | — | MISS | — |
| SEC-TH-163 | — | MISS | — |
| SEC-TH-164 | — | MISS | — |
| SEC-TH-165 | — | MISS | — |
| SEC-TH-166 | — | MISS | — |
| SEC-TH-167 | — | MISS | — |
| SEC-TH-168 | — | MISS | — |
| SEC-TH-169 | — | MISS | — |
| SEC-TH-170 | — | MISS | — |
| SEC-TH-171 | — | MISS | — |
| SEC-TH-172 | — | MISS | — |
| SEC-TH-173 | — | MISS | — |
| SEC-TH-174 | — | MISS | — |
| SEC-TH-175 | — | MISS | — |
| SEC-TH-176 | — | MISS | — |
| SEC-TH-177 | — | MISS | — |
| SEC-TH-178 | — | MISS | — |
| SEC-TH-179 | — | MISS | — |
| SEC-TH-180 | — | MISS | — |
| SEC-TH-181 | — | MISS | — |
| SEC-TH-182 | — | MISS | — |
| SEC-TH-183 | — | MISS | — |
| SEC-TH-184 | — | MISS | — |
| SEC-TH-185 | — | MISS | — |
| SEC-TH-186 | — | MISS | — |
| SEC-TH-187 | — | MISS | — |
| SEC-TH-188 | — | MISS | — |
| SEC-TH-189 | — | MISS | — |
| SEC-TH-190 | — | MISS | — |
| SEC-TH-191 | — | MISS | — |
| SEC-TH-192 | — | MISS | — |
| SEC-TH-193 | — | MISS | — |
| SEC-TH-194 | — | MISS | — |
| SEC-TH-195 | — | MISS | — |
| SEC-TH-196 | — | MISS | — |
| SEC-TH-197 | — | MISS | — |
| SEC-TH-198 | — | MISS | — |
| SEC-TH-199 | — | MISS | — |
| SEC-TH-200 | — | MISS | — |
| SEC-TH-201 | — | MISS | — |
| SEC-TH-202 | — | MISS | — |
| SEC-TH-203 | — | MISS | — |
| SEC-TH-204 | — | MISS | — |
| SEC-TH-205 | — | MISS | — |
| SEC-TH-206 | — | MISS | — |
| SEC-TH-207 | — | MISS | — |
| SEC-TH-208 | — | MISS | — |
| SEC-TH-209 | — | MISS | — |
| SEC-TH-210 | — | MISS | — |
| SEC-TH-211 | — | MISS | — |
| SEC-TH-212 | — | MISS | — |
| SEC-TH-213 | — | MISS | — |
| SEC-TH-214 | — | MISS | — |
| SEC-TH-215 | — | MISS | — |
| SEC-TH-216 | — | MISS | — |
| SEC-TH-217 | — | MISS | — |
| SEC-TH-218 | — | MISS | — |
| SEC-TH-219 | — | MISS | — |
| SEC-TH-220 | — | MISS | — |
| SEC-TH-221 | — | MISS | — |
| SEC-TH-222 | — | MISS | — |
| SEC-TH-223 | — | MISS | — |
| SEC-TH-224 | — | MISS | — |
| SEC-TH-225 | — | MISS | — |
| SEC-TH-226 | — | MISS | — |
| SEC-TH-227 | — | MISS | — |
| SEC-TH-228 | — | MISS | — |
| SEC-TH-229 | — | MISS | — |
| SEC-TH-230 | — | MISS | — |
| SEC-TH-231 | — | MISS | — |
| SEC-TH-232 | — | MISS | — |
| SEC-TH-233 | — | MISS | — |
| SEC-TH-234 | — | MISS | — |
| SEC-TH-235 | — | MISS | — |
| SEC-TH-236 | — | MISS | — |
| SEC-TH-237 | — | MISS | — |
| SEC-TH-238 | — | MISS | — |
| SEC-TH-239 | — | MISS | — |
| SEC-TH-240 | — | MISS | — |
| SEC-TH-241 | — | MISS | — |
| SEC-TH-242 | — | MISS | — |
| SEC-TH-243 | — | MISS | — |
| SEC-TH-244 | — | MISS | — |
| SEC-TH-245 | — | MISS | — |
| SEC-TH-246 | — | MISS | — |
| SEC-TH-247 | — | MISS | — |
| SEC-TH-248 | — | MISS | — |
| SEC-TH-249 | — | MISS | — |
| SEC-TH-250 | — | MISS | — |
| SEC-TH-251 | — | MISS | — |
| SEC-TH-252 | — | MISS | — |
| SEC-TH-253 | — | MISS | — |
| SEC-TH-254 | — | MISS | — |
| SEC-TH-255 | — | MISS | — |
| SEC-TH-256 | — | MISS | — |
| SEC-TH-257 | — | MISS | — |
| SEC-TH-258 | — | MISS | — |
| SEC-TH-259 | — | MISS | — |
| SEC-TH-260 | — | MISS | — |
| SEC-TH-261 | — | MISS | — |
| SEC-TH-262 | — | MISS | — |
| SEC-TH-263 | — | MISS | — |
| SEC-TH-264 | — | MISS | — |
| SEC-TH-265 | — | MISS | — |
| SEC-TH-266 | — | MISS | — |
| SEC-TH-267 | — | MISS | — |
| SEC-TH-268 | — | MISS | — |
| SEC-TH-269 | — | MISS | — |
| SEC-TH-270 | — | MISS | — |
| SEC-TH-271 | — | MISS | — |
| SEC-TH-272 | — | MISS | — |
| SEC-TH-273 | — | MISS | — |
| SEC-TH-274 | — | MISS | — |
| SEC-TH-275 | — | MISS | — |
| SEC-TH-276 | — | MISS | — |
| SEC-TH-277 | — | MISS | — |
| SEC-TH-278 | — | MISS | — |
| SEC-TH-279 | — | MISS | — |
| SEC-TH-280 | — | MISS | — |
| SEC-TH-281 | — | MISS | — |
| SEC-TH-282 | — | MISS | — |
| SEC-TH-283 | — | MISS | — |
| SEC-TH-284 | — | MISS | — |
| SEC-TH-285 | — | MISS | — |
| SEC-TH-286 | — | MISS | — |
| SEC-TH-287 | — | MISS | — |
| SEC-TH-288 | — | MISS | — |
| SEC-TH-289 | — | MISS | — |
| SEC-TH-290 | — | MISS | — |
| SEC-TH-291 | — | MISS | — |
| SEC-TH-292 | — | MISS | — |
| SEC-TH-293 | — | MISS | — |
| SEC-TH-294 | — | MISS | — |
| SEC-TH-295 | — | MISS | — |
| SEC-TH-296 | — | MISS | — |
| SEC-TH-297 | — | MISS | — |
| SEC-TH-298 | — | MISS | — |
| SEC-TH-299 | — | MISS | — |
| SEC-TH-300 | — | MISS | — |
| SEC-TH-301 | — | MISS | — |
| SEC-TH-302 | — | MISS | — |
| SEC-TH-303 | — | MISS | — |
| SEC-TH-304 | — | MISS | — |
| SEC-TH-305 | — | MISS | — |
| SEC-TH-306 | — | MISS | — |
| SEC-TH-307 | — | MISS | — |
| SEC-TH-308 | — | MISS | — |
| SEC-TH-309 | — | MISS | — |
| SEC-TH-310 | — | MISS | — |
| SEC-TH-311 | — | MISS | — |
| SEC-TH-312 | — | MISS | — |
| SEC-TH-313 | — | MISS | — |
| SEC-TH-314 | — | MISS | — |
| SEC-TH-315 | — | MISS | — |
| SEC-TH-316 | — | MISS | — |
| SEC-TH-317 | — | MISS | — |
| SEC-TH-318 | — | MISS | — |
| SEC-TH-319 | — | MISS | — |
| SEC-TH-320 | — | MISS | — |
| SEC-TH-321 | — | MISS | — |
| SEC-TH-322 | — | MISS | — |
| SEC-TH-323 | — | MISS | — |
| SEC-TH-324 | — | MISS | — |
| SEC-TH-325 | — | MISS | — |
| SEC-TH-326 | — | MISS | — |
| SEC-TH-327 | — | MISS | — |
| SEC-TH-328 | — | MISS | — |
| SEC-TH-329 | — | MISS | — |
| SEC-TH-330 | — | MISS | — |
| SEC-TH-331 | — | MISS | — |
| SEC-TH-332 | — | MISS | — |
| SEC-TH-333 | — | MISS | — |
| SEC-TH-334 | — | MISS | — |
| SEC-TH-335 | — | MISS | — |
| SEC-TH-336 | — | MISS | — |
| SEC-TH-337 | — | MISS | — |
| SEC-TH-338 | — | MISS | — |
| SEC-TH-339 | — | MISS | — |
| SEC-TH-340 | — | MISS | — |
| SEC-TH-341 | — | MISS | — |
| SEC-TH-342 | — | MISS | — |
| SEC-TH-343 | — | MISS | — |
| SEC-TH-344 | — | MISS | — |
| SEC-TH-345 | — | MISS | — |
| SEC-TH-346 | — | MISS | — |
| SEC-TH-347 | — | MISS | — |
| SEC-TH-348 | — | MISS | — |
| SEC-TH-349 | — | MISS | — |
| SEC-TH-350 | — | MISS | — |
| SEC-TH-351 | — | MISS | — |
| SEC-TH-352 | — | MISS | — |
| SEC-TH-353 | — | MISS | — |
| SEC-TH-354 | — | MISS | — |
| SEC-TH-355 | — | MISS | — |
| SEC-TH-356 | — | MISS | — |
| SEC-TH-357 | — | MISS | — |
| SEC-TH-358 | — | MISS | — |
| SEC-TH-359 | — | MISS | — |
| SEC-TH-360 | — | MISS | — |
| SEC-TH-361 | — | MISS | — |
| SEC-TH-362 | — | MISS | — |
| SEC-TH-363 | — | MISS | — |
| SEC-TH-364 | — | MISS | — |
| SEC-TH-365 | — | MISS | — |
| SEC-TH-366 | — | MISS | — |
| SEC-TH-367 | — | MISS | — |
| SEC-TH-368 | — | MISS | — |
| SEC-TH-369 | — | MISS | — |
| SEC-TH-370 | — | MISS | — |
| SEC-TH-371 | — | MISS | — |
| SEC-TH-372 | — | MISS | — |
| SEC-TH-373 | — | MISS | — |
| SEC-TH-374 | — | MISS | — |
| SEC-TH-375 | — | MISS | — |
| SEC-TH-376 | — | MISS | — |
| SEC-TH-377 | — | MISS | — |
| SEC-TH-378 | — | MISS | — |
| SEC-TH-379 | — | MISS | — |
| SEC-TH-380 | — | MISS | — |
| SEC-TH-381 | — | MISS | — |
| SEC-TH-382 | — | MISS | — |
| SEC-TH-383 | — | MISS | — |
| SEC-TH-384 | — | MISS | — |
| SEC-TH-385 | — | MISS | — |
| SEC-TH-386 | — | MISS | — |
| SEC-TH-387 | — | MISS | — |
| SEC-TH-388 | — | MISS | — |
| SEC-TH-389 | — | MISS | — |
| SEC-TH-390 | — | MISS | — |
| SEC-TH-391 | — | MISS | — |
| SEC-TH-392 | — | MISS | — |
| SEC-TH-393 | — | MISS | — |
| SEC-TH-394 | — | MISS | — |
| SEC-TH-395 | — | MISS | — |
| SEC-TH-396 | — | MISS | — |
| SEC-TH-397 | — | MISS | — |
| SEC-TH-399 | — | MISS | — |
| SEC-TH-400 | — | MISS | — |
| SEC-TH-401 | — | MISS | — |
| SEC-TH-402 | — | MISS | — |
| SEC-TH-403 | — | MISS | — |
| SEC-TH-404 | — | MISS | — |
| SEC-TH-405 | — | MISS | — |
| SEC-TH-406 | — | MISS | — |
| SEC-TH-407 | — | MISS | — |
| SEC-TH-408 | — | MISS | — |
| SEC-TH-409 | — | MISS | — |
| SEC-TH-410 | — | MISS | — |
| SEC-TH-411 | — | MISS | — |
| SEC-TH-412 | — | MISS | — |
| SEC-TH-413 | — | MISS | — |
| SEC-TH-414 | — | MISS | — |
| SEC-TH-415 | — | MISS | — |
| SEC-TH-416 | — | MISS | — |
| SEC-TH-417 | — | MISS | — |
| SEC-TH-418 | — | MISS | — |
| SEC-TH-419 | — | MISS | — |
| SEC-TH-420 | — | MISS | — |
| SEC-TH-421 | — | MISS | — |
| SEC-TH-422 | — | MISS | — |
| SEC-TH-423 | — | MISS | — |
| SEC-TH-424 | — | MISS | — |
| SEC-TH-425 | — | MISS | — |
| SEC-TH-426 | — | MISS | — |
| SEC-TH-427 | — | MISS | — |
| SEC-TH-428 | — | MISS | — |
| SEC-TH-429 | — | MISS | — |
| SEC-TH-430 | — | MISS | — |
| SEC-TH-431 | — | MISS | — |
| SEC-TH-432 | — | MISS | — |
| SEC-TH-433 | — | MISS | — |
| SEC-TH-434 | — | MISS | — |
| SEC-TH-435 | — | MISS | — |
| SEC-TH-436 | — | MISS | — |
| SEC-TH-437 | — | MISS | — |
| SEC-TH-438 | — | MISS | — |
| SEC-TH-439 | — | MISS | — |
| SEC-TH-440 | — | MISS | — |
| SEC-TH-441 | — | MISS | — |
| SEC-TH-442 | — | MISS | — |
| SEC-TH-443 | — | MISS | — |
| SEC-TH-444 | — | MISS | — |
| SEC-TH-445 | — | MISS | — |
| SEC-TH-446 | — | MISS | — |
| SEC-TH-447 | — | MISS | — |
| SEC-TH-448 | — | MISS | — |
| SEC-TH-449 | — | MISS | — |
| SEC-TH-451 | — | MISS | — |
| SEC-TH-452 | — | MISS | — |
| SEC-TH-453 | — | MISS | — |
| SEC-TH-454 | — | MISS | — |
| SEC-TH-455 | — | MISS | — |
| SEC-TH-456 | — | MISS | — |
| SEC-TH-457 | — | MISS | — |
| SEC-TH-458 | — | MISS | — |
| SEC-TH-459 | — | MISS | — |
| SEC-TH-460 | — | MISS | — |
| SEC-TH-461 | — | MISS | — |
| SEC-TH-462 | — | MISS | — |
| SEC-TH-463 | — | MISS | — |
| SEC-TH-464 | — | MISS | — |
| SEC-TH-465 | — | MISS | — |
| SEC-TH-466 | — | MISS | — |
| SEC-TH-467 | — | MISS | — |
| SEC-TH-468 | — | MISS | — |
| SEC-TH-469 | — | MISS | — |
| SEC-TH-470 | — | MISS | — |
| SEC-TH-471 | — | MISS | — |
| SEC-TH-472 | — | MISS | — |
| SEC-TH-473 | — | MISS | — |
| SEC-TH-474 | — | MISS | — |
| SEC-TH-475 | — | MISS | — |
| SEC-TH-476 | — | MISS | — |
| SEC-TH-477 | — | MISS | — |
| SEC-TH-478 | — | MISS | — |
| SEC-TH-479 | — | MISS | — |
| SEC-TH-480 | — | MISS | — |
| SEC-TH-481 | — | MISS | — |
| SEC-TH-482 | — | MISS | — |
| SEC-TH-483 | — | MISS | — |
| SEC-TH-484 | — | MISS | — |
| SEC-TH-485 | — | MISS | — |
| SEC-TH-486 | — | MISS | — |
| SEC-TH-487 | — | MISS | — |
| SEC-TH-488 | — | MISS | — |
| SEC-TH-489 | — | MISS | — |
| SEC-TH-490 | — | MISS | — |
| SEC-TH-491 | — | MISS | — |
| SEC-TH-492 | — | MISS | — |
| SEC-TH-493 | — | MISS | — |
| SEC-TH-494 | — | MISS | — |
| SEC-TH-495 | — | MISS | — |
| SEC-TH-496 | — | MISS | — |
| SEC-TH-497 | — | MISS | — |
| SEC-TH-498 | — | MISS | — |
| SEC-TH-499 | — | MISS | — |
| SEC-TH-500 | — | MISS | — |
| SEC-TH-501 | — | MISS | — |
| SEC-TH-502 | — | MISS | — |
| SEC-TH-503 | — | MISS | — |
| SEC-TH-504 | — | MISS | — |
| SEC-TH-505 | — | MISS | — |
| SEC-TH-506 | — | MISS | — |
| SEC-TH-507 | — | MISS | — |
| SEC-TH-508 | — | MISS | — |
| SEC-TH-509 | — | MISS | — |
| SEC-TH-510 | — | MISS | — |
| SEC-TH-511 | — | MISS | — |
| SEC-TH-512 | — | MISS | — |
| SEC-TH-513 | — | MISS | — |
| SEC-TH-514 | — | MISS | — |
| SEC-TH-515 | — | MISS | — |
| SEC-TH-516 | — | MISS | — |
| SEC-TH-517 | — | MISS | — |
| SEC-TH-518 | — | MISS | — |
| SEC-TH-519 | — | MISS | — |
| SEC-TH-520 | — | MISS | — |
| SEC-TH-521 | — | MISS | — |
| SEC-TH-522 | — | MISS | — |
| SEC-TH-523 | — | MISS | — |
| SEC-TH-524 | — | MISS | — |
| SEC-TH-525 | — | MISS | — |
| SEC-TH-526 | — | MISS | — |
| SEC-TH-527 | — | MISS | — |
| SEC-TH-528 | — | MISS | — |
| SEC-TH-529 | — | MISS | — |
| SEC-TH-530 | — | MISS | — |
| SEC-TH-531 | — | MISS | — |
| SEC-TH-532 | — | MISS | — |
| SEC-TH-533 | — | MISS | — |
| SEC-TH-534 | — | MISS | — |
| SEC-TH-535 | — | MISS | — |
| SEC-TH-536 | — | MISS | — |
| SEC-TH-537 | — | MISS | — |
| SEC-TH-538 | — | MISS | — |
| SEC-TH-539 | — | MISS | — |
| SEC-TH-540 | — | MISS | — |
| SEC-TH-541 | — | MISS | — |
| SEC-TH-542 | — | MISS | — |
| SEC-TH-543 | — | MISS | — |
| SEC-TH-544 | — | MISS | — |
| SEC-TH-545 | — | MISS | — |
| SEC-TH-546 | — | MISS | — |
| SEC-TH-547 | — | MISS | — |
| SEC-TH-548 | — | MISS | — |
| SEC-TH-549 | — | MISS | — |
| SEC-TH-550 | — | MISS | — |
| SEC-TH-551 | — | MISS | — |
| SEC-TH-553 | — | MISS | — |
| SEC-TH-554 | — | MISS | — |
| SEC-TH-555 | — | MISS | — |
| SEC-TH-556 | — | MISS | — |
| SEC-TH-557 | — | MISS | — |
| SEC-TH-558 | — | MISS | — |
| SEC-TH-559 | — | MISS | — |
| SEC-TH-560 | — | MISS | — |
| SEC-TH-561 | — | MISS | — |
| SEC-TH-562 | — | MISS | — |
| SEC-TH-563 | — | MISS | — |
| SEC-TH-564 | — | MISS | — |
| SEC-TH-565 | — | MISS | — |
| SEC-TH-566 | — | MISS | — |
| SEC-TH-567 | — | MISS | — |
| SEC-TH-568 | — | MISS | — |
| SEC-TH-569 | — | MISS | — |
| SEC-TH-570 | — | MISS | — |
| SEC-TH-571 | — | MISS | — |
| SEC-TH-572 | — | MISS | — |
| SEC-TH-573 | — | MISS | — |
| SEC-TH-574 | — | MISS | — |
| SEC-TH-575 | — | MISS | — |
| SEC-TH-576 | — | MISS | — |
| SEC-TH-577 | — | MISS | — |
| SEC-TH-578 | — | MISS | — |
| SEC-TH-579 | — | MISS | — |
| SEC-TH-580 | — | MISS | — |
| SEC-TH-581 | — | MISS | — |
| SEC-TH-582 | — | MISS | — |
| SEC-TH-583 | — | MISS | — |
| SEC-TH-584 | — | MISS | — |
| SEC-TH-585 | — | MISS | — |
| SEC-TH-586 | — | MISS | — |
| SEC-TH-587 | — | MISS | — |
| SEC-TH-588 | — | MISS | — |
| SEC-TH-589 | — | MISS | — |
| SEC-TH-590 | — | MISS | — |
| SEC-TH-591 | — | MISS | — |
| SEC-TH-592 | — | MISS | — |
| SEC-TH-593 | — | MISS | — |
| SEC-TH-594 | — | MISS | — |
| SEC-TH-595 | — | MISS | — |
| SEC-TH-596 | — | MISS | — |
| SEC-TH-597 | — | MISS | — |
| SEC-TH-598 | — | MISS | — |
| SEC-TH-599 | — | MISS | — |
| SEC-TH-600 | — | MISS | — |
| SEC-TH-601 | — | MISS | — |
| SEC-TH-602 | — | MISS | — |
| SEC-TH-603 | — | MISS | — |
| SEC-TH-604 | — | MISS | — |
| SEC-TH-605 | — | MISS | — |
| SEC-TH-606 | — | MISS | — |
| SEC-TH-607 | — | MISS | — |
| SEC-TH-608 | — | MISS | — |
| SEC-TH-609 | — | MISS | — |
| SEC-TH-610 | — | MISS | — |
| SEC-TH-611 | — | MISS | — |
| SEC-TH-612 | — | MISS | — |
| SEC-TH-613 | — | MISS | — |
| SEC-TH-614 | — | MISS | — |
| SEC-TH-615 | — | MISS | — |
| SEC-TH-616 | — | MISS | — |
| SEC-TH-617 | — | MISS | — |
| SEC-TH-618 | — | MISS | — |
| SEC-TH-619 | — | MISS | — |
| SEC-TH-620 | — | MISS | — |
| SEC-TH-621 | — | MISS | — |
| SEC-TH-622 | — | MISS | — |
| SEC-TH-623 | — | MISS | — |
| SEC-TH-624 | — | MISS | — |
| SEC-TH-625 | — | MISS | — |
| SEC-TH-626 | — | MISS | — |
| SEC-TH-627 | — | MISS | — |
| SEC-TH-628 | — | MISS | — |
| SEC-TH-629 | — | MISS | — |
| SEC-TH-630 | — | MISS | — |
| SEC-TH-631 | — | MISS | — |
| SEC-TH-632 | — | MISS | — |
| SEC-TH-633 | — | MISS | — |
| SEC-TH-634 | — | MISS | — |
| SEC-TH-635 | — | MISS | — |
| SEC-TH-636 | — | MISS | — |
| SEC-TH-637 | — | MISS | — |
| SEC-TH-638 | — | MISS | — |
| SEC-TH-639 | — | MISS | — |
| SEC-TH-640 | — | MISS | — |
| SEC-TH-641 | — | MISS | — |
| SEC-TH-642 | — | MISS | — |
| SEC-TH-643 | — | MISS | — |
| SEC-TH-644 | — | MISS | — |
| SEC-TH-645 | — | MISS | — |
| SEC-TH-646 | — | MISS | — |
| SEC-TH-647 | — | MISS | — |
| SEC-TH-648 | — | MISS | — |
| SEC-TH-649 | — | MISS | — |
| SEC-TH-650 | — | MISS | — |
| SEC-TH-651 | — | MISS | — |
| SEC-TH-652 | — | MISS | — |
| SEC-TH-653 | — | MISS | — |
| SEC-TH-654 | — | MISS | — |
| SEC-TH-655 | — | MISS | — |
| SEC-TH-656 | — | MISS | — |
| SEC-TH-657 | — | MISS | — |
| SEC-TH-658 | — | MISS | — |
| SEC-TH-659 | — | MISS | — |
| SEC-TH-660 | — | MISS | — |
| SEC-TH-661 | — | MISS | — |
| SEC-TH-662 | — | MISS | — |
| SEC-TH-663 | — | MISS | — |
| SEC-TH-664 | — | MISS | — |
| SEC-TH-665 | — | MISS | — |
| SEC-TH-666 | — | MISS | — |
| SEC-TH-667 | — | MISS | — |
| SEC-TH-668 | — | MISS | — |
| SEC-TH-669 | — | MISS | — |
| SEC-TH-670 | — | MISS | — |
| SEC-TH-671 | — | MISS | — |
| SEC-TH-672 | — | MISS | — |
| SEC-TH-673 | — | MISS | — |
| SEC-TH-674 | — | MISS | — |
| SEC-TH-675 | — | MISS | — |
| SEC-TH-676 | — | MISS | — |
| SEC-TH-677 | — | MISS | — |
| SEC-TH-678 | — | MISS | — |
| SEC-TH-679 | — | MISS | — |
| SEC-TH-680 | — | MISS | — |
| SEC-TH-681 | — | MISS | — |
| SEC-TH-682 | — | MISS | — |
| SEC-TH-683 | — | MISS | — |
| SEC-TH-684 | — | MISS | — |
| SEC-TH-685 | — | MISS | — |
| SEC-TH-686 | — | MISS | — |
| SEC-TH-687 | — | MISS | — |
| SEC-TH-688 | — | MISS | — |
| SEC-TH-689 | — | MISS | — |
| SEC-TH-690 | — | MISS | — |
| SEC-TH-691 | — | MISS | — |
| SEC-TH-692 | — | MISS | — |
| SEC-TH-693 | — | MISS | — |
| SEC-TH-694 | — | MISS | — |
| SEC-TH-695 | — | MISS | — |
| SEC-TH-696 | — | MISS | — |
| SEC-TH-697 | — | MISS | — |
| SEC-TH-698 | — | MISS | — |
| SEC-TH-699 | — | MISS | — |
| SEC-TH-700 | — | MISS | — |
| SEC-TH-701 | — | MISS | — |
| SEC-TH-702 | — | MISS | — |
| SEC-TH-703 | — | MISS | — |
| SEC-TH-704 | — | MISS | — |
| SEC-TH-705 | — | MISS | — |
| SEC-TH-706 | — | MISS | — |
| SEC-TH-707 | — | MISS | — |
| SEC-TH-708 | — | MISS | — |
| SEC-TH-709 | — | MISS | — |
| SEC-TH-710 | — | MISS | — |
| SEC-TH-711 | — | MISS | — |
| SEC-TH-712 | — | MISS | — |
| SEC-TH-713 | — | MISS | — |
| SEC-TH-714 | — | MISS | — |
| SEC-TH-715 | — | MISS | — |
| SEC-TH-716 | — | MISS | — |
| SEC-TH-717 | — | MISS | — |
| SEC-TH-718 | — | MISS | — |
| SEC-TH-719 | — | MISS | — |
| SEC-TH-720 | — | MISS | — |
| SEC-TH-721 | — | MISS | — |
| SEC-TH-722 | — | MISS | — |
| SEC-TH-723 | — | MISS | — |
| SEC-TH-724 | — | MISS | — |
| SEC-TH-725 | — | MISS | — |
| SEC-TH-726 | — | MISS | — |
| SEC-TH-727 | — | MISS | — |
| SEC-TH-728 | — | MISS | — |
| SEC-TH-729 | — | MISS | — |
| SEC-TH-730 | — | MISS | — |
| SEC-TH-731 | — | MISS | — |
| SEC-TH-732 | — | MISS | — |
| SEC-TH-733 | — | MISS | — |
| SEC-TH-734 | — | MISS | — |
| SEC-TH-735 | — | MISS | — |
| SEC-TH-736 | — | MISS | — |
| SEC-TH-737 | — | MISS | — |
| SEC-TH-738 | — | MISS | — |
| SEC-TH-739 | — | MISS | — |
| SEC-TH-740 | — | MISS | — |
| SEC-TH-741 | — | MISS | — |
| SEC-TH-742 | — | MISS | — |
| SEC-TH-743 | — | MISS | — |
| SEC-TH-744 | — | MISS | — |
| SEC-TH-745 | — | MISS | — |
| SEC-TH-746 | — | MISS | — |
| SEC-TH-747 | — | MISS | — |
| SEC-TH-748 | — | MISS | — |
| SEC-TH-749 | — | MISS | — |
| SEC-TH-750 | — | MISS | — |
| SEC-TH-751 | — | MISS | — |
| SEC-TH-752 | — | MISS | — |
| SEC-TH-753 | — | MISS | — |
| SEC-TH-754 | — | MISS | — |
| SEC-TH-755 | — | MISS | — |
| SEC-TH-756 | — | MISS | — |
| SEC-TH-757 | — | MISS | — |
| SEC-TH-758 | — | MISS | — |
| SEC-TH-759 | — | MISS | — |
| SEC-TH-760 | — | MISS | — |
| SEC-TH-761 | — | MISS | — |
| SEC-TH-762 | — | MISS | — |
| SEC-TH-763 | — | MISS | — |
| SEC-TH-764 | — | MISS | — |
| SEC-TH-765 | — | MISS | — |
| SEC-TH-766 | — | MISS | — |
| SEC-TH-767 | — | MISS | — |
| SEC-TH-768 | — | MISS | — |
| SEC-TH-769 | — | MISS | — |
| SEC-TH-770 | — | MISS | — |
| SEC-TH-771 | — | MISS | — |
| SEC-TH-772 | — | MISS | — |
| SEC-TH-773 | — | MISS | — |
| SEC-TH-774 | — | MISS | — |
| SEC-TH-775 | — | MISS | — |
| SEC-TH-776 | — | MISS | — |
| SEC-TH-777 | — | MISS | — |
| SEC-TH-778 | — | MISS | — |
| SEC-TH-779 | — | MISS | — |
| SEC-TH-780 | — | MISS | — |
| SEC-TH-781 | — | MISS | — |
| SEC-TH-782 | — | MISS | — |
| SEC-TH-783 | — | MISS | — |
| SEC-TH-784 | — | MISS | — |
| SEC-TH-785 | — | MISS | — |
| SEC-TH-786 | — | MISS | — |
| SEC-TH-787 | — | MISS | — |
| SEC-TH-788 | — | MISS | — |
| SEC-TH-789 | — | MISS | — |
| SEC-TH-790 | — | MISS | — |
| SGA-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SGA-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SGA-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SGA-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SGA-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SGA-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SGA-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SGA-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SGA-009 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SGA-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SGA-011 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SGA-012 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SGA-013 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SGA-014 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SGA-015 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SGA-016 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SGA-017 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SGA-018 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SGA-019 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SGA-020 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SGA-021 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SGA-022 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SGA-023 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SGA-024 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SGA-025 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SGA-026 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SGA-027 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SGA-028 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SGA-029 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SGA-030 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-009 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-011 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-012 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-013 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-014 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-015 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-016 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-017 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-018 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-019 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-020 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-021 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-022 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-023 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-024 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-025 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-026 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-027 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-028 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-029 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-030 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-031 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-032 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-033 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-034 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-035 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-036 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-037 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-038 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-039 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-040 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-041 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-042 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-043 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-044 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-045 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-046 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-047 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-048 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-049 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-050 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-051 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-052 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-053 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-054 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-071 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-072 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-073 | `core/gold-standard-testbed/application-test.properties` | HIT | Semgrep + marker |
| SPR-074 | `core/gold-standard-testbed/application-test.properties` | HIT | Semgrep + marker |
| SPR-075 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-076 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-077 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-078 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-079 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-080 | `core/gold-standard-testbed/application-test.properties` | HIT | Semgrep + marker |
| SPR-081 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-082 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-083 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-084 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-085 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-086 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-087 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-088 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-089 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-090 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-091 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-092 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-093 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-094 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-095 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-096 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-097 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-098 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-099 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-100 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-101 | `core/gold-standard-testbed/application-test.properties` | HIT | Semgrep + marker |
| SPR-102 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-103 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| SPR-104 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-105 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-106 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-107 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-108 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-109 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-110 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-111 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-112 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-113 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-114 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-115 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-116 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-117 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-118 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-119 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-120 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-121 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-122 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SPR-123 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SQD-001 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| SQD-002 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| SQD-003 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| SQD-004 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| SQD-005 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| SQD-006 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| SQD-007 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| SQD-008 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| SQD-009 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| SQD-010 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| SQD-011 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| SQD-012 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| SQD-013 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| SQD-014 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| SQD-015 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| SSR-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SSR-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SSR-003 | `core/gold-standard-testbed/advanced_ssrf_feign.java` | HIT | Marker (testbed) |
| SSR-004 | `core/gold-standard-testbed/advanced_ssrf_feign.java` | HIT | Marker (testbed) |
| SSR-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SSR-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SSR-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SSR-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SSR-009 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SSR-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SSR-011 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SSR-012 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| SSR-013 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| TIM-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| TIM-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| TIM-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| TIM-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| TIM-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| TIM-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| TIM-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| TIM-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| TIM-009 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| TIM-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| TIM-011 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| TIM-012 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| TIM-013 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| TIM-014 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| TIM-015 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13F-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13F-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13F-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13F-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13F-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13F-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13F-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13F-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13F-009 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13F-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13F-011 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13F-012 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13F-013 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13F-014 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13F-015 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13F-016 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13F-017 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13F-018 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13F-019 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13F-020 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13J-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13J-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13J-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13J-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13J-005 | `core/gold-standard-testbed/api_strict_schema_vulnerable.java` | HIT | Marker (testbed) |
| V13J-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13J-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13J-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13J-009 | `core/gold-standard-testbed/api_strict_schema_vulnerable.java` | HIT | Marker (testbed) |
| V13J-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13J-011 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13J-012 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13J-013 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13J-014 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13J-015 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13J-016 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13J-017 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13J-018 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13J-019 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| V13J-020 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| VUL-CVE-2005-2547 | — | MISS | — |
| VUL-CVE-2006-2898 | — | MISS | — |
| VUL-CVE-2006-3467 | — | MISS | — |
| VUL-CVE-2006-4168 | — | MISS | — |
| VUL-CVE-2006-4345 | — | MISS | — |
| VUL-CVE-2006-6870 | — | MISS | — |
| VUL-CVE-2007-2293 | — | MISS | — |
| VUL-CVE-2007-2297 | — | MISS | — |
| VUL-CVE-2007-2645 | — | MISS | — |
| VUL-CVE-2007-6351 | — | MISS | — |
| VUL-CVE-2007-6352 | — | MISS | — |
| VUL-CVE-2008-0544 | — | MISS | — |
| VUL-CVE-2008-1807 | — | MISS | — |
| VUL-CVE-2008-2235 | — | MISS | — |
| VUL-CVE-2008-4201 | — | MISS | — |
| VUL-CVE-2008-4867 | — | MISS | — |
| VUL-CVE-2009-0037 | — | MISS | — |
| VUL-CVE-2009-0385 | — | MISS | — |
| VUL-CVE-2009-1379 | — | MISS | — |
| VUL-CVE-2009-1959 | — | MISS | — |
| VUL-CVE-2009-3895 | — | MISS | — |
| VUL-CVE-2010-0012 | — | MISS | — |
| VUL-CVE-2010-0743 | — | MISS | — |
| VUL-CVE-2010-1156 | — | MISS | — |
| VUL-CVE-2010-1224 | — | MISS | — |
| VUL-CVE-2010-1853 | — | MISS | — |
| VUL-CVE-2010-2249 | — | MISS | — |
| VUL-CVE-2010-3814 | — | MISS | — |
| VUL-CVE-2010-4706 | — | MISS | — |
| VUL-CVE-2011-1098 | — | MISS | — |
| VUL-CVE-2011-1499 | — | MISS | — |
| VUL-CVE-2011-1843 | — | MISS | — |
| VUL-CVE-2011-2161 | — | MISS | — |
| VUL-CVE-2011-3328 | — | MISS | — |
| VUL-CVE-2012-1107 | — | MISS | — |
| VUL-CVE-2012-1108 | — | MISS | — |
| VUL-CVE-2012-1162 | — | MISS | — |
| VUL-CVE-2012-1163 | — | MISS | — |
| VUL-CVE-2012-1836 | — | MISS | — |
| VUL-CVE-2012-2772 | — | MISS | — |
| VUL-CVE-2012-2774 | — | MISS | — |
| VUL-CVE-2012-2775 | — | MISS | — |
| VUL-CVE-2012-2776 | — | MISS | — |
| VUL-CVE-2012-2777 | — | MISS | — |
| VUL-CVE-2012-2779 | — | MISS | — |
| VUL-CVE-2012-2782 | — | MISS | — |
| VUL-CVE-2012-2783 | — | MISS | — |
| VUL-CVE-2012-2785 | — | MISS | — |
| VUL-CVE-2012-2786 | — | MISS | — |
| VUL-CVE-2012-2787 | — | MISS | — |
| VUL-CVE-2012-2788 | — | MISS | — |
| VUL-CVE-2012-2789 | — | MISS | — |
| VUL-CVE-2012-2790 | — | MISS | — |
| VUL-CVE-2012-2791 | — | MISS | — |
| VUL-CVE-2012-2792 | — | MISS | — |
| VUL-CVE-2012-2793 | — | MISS | — |
| VUL-CVE-2012-2794 | — | MISS | — |
| VUL-CVE-2012-2795 | — | MISS | — |
| VUL-CVE-2012-2796 | — | MISS | — |
| VUL-CVE-2012-2797 | — | MISS | — |
| VUL-CVE-2012-2798 | — | MISS | — |
| VUL-CVE-2012-2799 | — | MISS | — |
| VUL-CVE-2012-2800 | — | MISS | — |
| VUL-CVE-2012-2801 | — | MISS | — |
| VUL-CVE-2012-2802 | — | MISS | — |
| VUL-CVE-2012-2803 | — | MISS | — |
| VUL-CVE-2012-2804 | — | MISS | — |
| VUL-CVE-2012-2806 | — | MISS | — |
| VUL-CVE-2012-2814 | — | MISS | — |
| VUL-CVE-2012-2836 | — | MISS | — |
| VUL-CVE-2012-2837 | — | MISS | — |
| VUL-CVE-2012-2840 | — | MISS | — |
| VUL-CVE-2012-2841 | — | MISS | — |
| VUL-CVE-2012-3358 | — | MISS | — |
| VUL-CVE-2012-4504 | — | MISS | — |
| VUL-CVE-2012-5671 | — | MISS | — |
| VUL-CVE-2012-6617 | — | MISS | — |
| VUL-CVE-2012-6618 | — | MISS | — |
| VUL-CVE-2012-6696 | — | MISS | — |
| VUL-CVE-2012-6697 | — | MISS | — |
| VUL-CVE-2013-0249 | — | MISS | — |
| VUL-CVE-2013-0250 | — | MISS | — |
| VUL-CVE-2013-0844 | — | MISS | — |
| VUL-CVE-2013-0845 | — | MISS | — |
| VUL-CVE-2013-0846 | — | MISS | — |
| VUL-CVE-2013-0847 | — | MISS | — |
| VUL-CVE-2013-0848 | — | MISS | — |
| VUL-CVE-2013-0849 | — | MISS | — |
| VUL-CVE-2013-0850 | — | MISS | — |
| VUL-CVE-2013-0851 | — | MISS | — |
| VUL-CVE-2013-0852 | — | MISS | — |
| VUL-CVE-2013-0853 | — | MISS | — |
| VUL-CVE-2013-0854 | — | MISS | — |
| VUL-CVE-2013-0855 | — | MISS | — |
| VUL-CVE-2013-0856 | — | MISS | — |
| VUL-CVE-2013-0857 | — | MISS | — |
| VUL-CVE-2013-0858 | — | MISS | — |
| VUL-CVE-2013-0859 | — | MISS | — |
| VUL-CVE-2013-0860 | — | MISS | — |
| VUL-CVE-2013-0861 | — | MISS | — |
| VUL-CVE-2013-0862 | — | MISS | — |
| VUL-CVE-2013-0863 | — | MISS | — |
| VUL-CVE-2013-0864 | — | MISS | — |
| VUL-CVE-2013-0865 | — | MISS | — |
| VUL-CVE-2013-0866 | — | MISS | — |
| VUL-CVE-2013-0867 | — | MISS | — |
| VUL-CVE-2013-0868 | — | MISS | — |
| VUL-CVE-2013-0869 | — | MISS | — |
| VUL-CVE-2013-0870 | — | MISS | — |
| VUL-CVE-2013-0872 | — | MISS | — |
| VUL-CVE-2013-0873 | — | MISS | — |
| VUL-CVE-2013-0874 | — | MISS | — |
| VUL-CVE-2013-0875 | — | MISS | — |
| VUL-CVE-2013-0876 | — | MISS | — |
| VUL-CVE-2013-0877 | — | MISS | — |
| VUL-CVE-2013-0878 | — | MISS | — |
| VUL-CVE-2013-0894 | — | MISS | — |
| VUL-CVE-2013-2142 | — | MISS | — |
| VUL-CVE-2013-2276 | — | MISS | — |
| VUL-CVE-2013-2277 | — | MISS | — |
| VUL-CVE-2013-2495 | — | MISS | — |
| VUL-CVE-2013-2496 | — | MISS | — |
| VUL-CVE-2013-3670 | — | MISS | — |
| VUL-CVE-2013-3671 | — | MISS | — |
| VUL-CVE-2013-3672 | — | MISS | — |
| VUL-CVE-2013-3673 | — | MISS | — |
| VUL-CVE-2013-3674 | — | MISS | — |
| VUL-CVE-2013-3675 | — | MISS | — |
| VUL-CVE-2013-4118 | — | MISS | — |
| VUL-CVE-2013-4119 | — | MISS | — |
| VUL-CVE-2013-4263 | — | MISS | — |
| VUL-CVE-2013-4264 | — | MISS | — |
| VUL-CVE-2013-4265 | — | MISS | — |
| VUL-CVE-2013-4290 | — | MISS | — |
| VUL-CVE-2013-4393 | — | MISS | — |
| VUL-CVE-2013-6401 | — | MISS | — |
| VUL-CVE-2013-6473 | — | MISS | — |
| VUL-CVE-2013-6629 | — | MISS | — |
| VUL-CVE-2013-7008 | — | MISS | — |
| VUL-CVE-2013-7009 | — | MISS | — |
| VUL-CVE-2013-7010 | — | MISS | — |
| VUL-CVE-2013-7011 | — | MISS | — |
| VUL-CVE-2013-7012 | — | MISS | — |
| VUL-CVE-2013-7013 | — | MISS | — |
| VUL-CVE-2013-7014 | — | MISS | — |
| VUL-CVE-2013-7015 | — | MISS | — |
| VUL-CVE-2013-7016 | — | MISS | — |
| VUL-CVE-2013-7017 | — | MISS | — |
| VUL-CVE-2013-7018 | — | MISS | — |
| VUL-CVE-2013-7019 | — | MISS | — |
| VUL-CVE-2013-7020 | — | MISS | — |
| VUL-CVE-2013-7021 | — | MISS | — |
| VUL-CVE-2013-7022 | — | MISS | — |
| VUL-CVE-2013-7023 | — | MISS | — |
| VUL-CVE-2013-7024 | — | MISS | — |
| VUL-CVE-2013-7262 | — | MISS | — |
| VUL-CVE-2013-7283 | — | MISS | — |
| VUL-CVE-2013-7294 | — | MISS | — |
| VUL-CVE-2013-7449 | — | MISS | — |
| VUL-CVE-2014-125002 | — | MISS | — |
| VUL-CVE-2014-125003 | — | MISS | — |
| VUL-CVE-2014-125004 | — | MISS | — |
| VUL-CVE-2014-125005 | — | MISS | — |
| VUL-CVE-2014-125006 | — | MISS | — |
| VUL-CVE-2014-125007 | — | MISS | — |
| VUL-CVE-2014-125008 | — | MISS | — |
| VUL-CVE-2014-125009 | — | MISS | — |
| VUL-CVE-2014-125010 | — | MISS | — |
| VUL-CVE-2014-125011 | — | MISS | — |
| VUL-CVE-2014-125012 | — | MISS | — |
| VUL-CVE-2014-125013 | — | MISS | — |
| VUL-CVE-2014-125015 | — | MISS | — |
| VUL-CVE-2014-125016 | — | MISS | — |
| VUL-CVE-2014-125017 | — | MISS | — |
| VUL-CVE-2014-125018 | — | MISS | — |
| VUL-CVE-2014-125019 | — | MISS | — |
| VUL-CVE-2014-125020 | — | MISS | — |
| VUL-CVE-2014-125021 | — | MISS | — |
| VUL-CVE-2014-125022 | — | MISS | — |
| VUL-CVE-2014-125023 | — | MISS | — |
| VUL-CVE-2014-125024 | — | MISS | — |
| VUL-CVE-2014-125025 | — | MISS | — |
| VUL-CVE-2014-125106 | — | MISS | — |
| VUL-CVE-2014-2097 | — | MISS | — |
| VUL-CVE-2014-2098 | — | MISS | — |
| VUL-CVE-2014-2099 | — | MISS | — |
| VUL-CVE-2014-2263 | — | MISS | — |
| VUL-CVE-2014-3570 | — | MISS | — |
| VUL-CVE-2014-3571 | — | MISS | — |
| VUL-CVE-2014-3572 | — | MISS | — |
| VUL-CVE-2014-3741 | — | MISS | — |
| VUL-CVE-2014-3985 | — | MISS | — |
| VUL-CVE-2014-4501 | — | MISS | — |
| VUL-CVE-2014-4502 | — | MISS | — |
| VUL-CVE-2014-4609 | — | MISS | — |
| VUL-CVE-2014-4610 | — | MISS | — |
| VUL-CVE-2014-5271 | — | MISS | — |
| VUL-CVE-2014-5272 | — | MISS | — |
| VUL-CVE-2014-5461 | — | MISS | — |
| VUL-CVE-2014-7937 | — | MISS | — |
| VUL-CVE-2014-8176 | — | MISS | — |
| VUL-CVE-2014-8275 | — | MISS | — |
| VUL-CVE-2014-8541 | — | MISS | — |
| VUL-CVE-2014-8542 | — | MISS | — |
| VUL-CVE-2014-8543 | — | MISS | — |
| VUL-CVE-2014-8544 | — | MISS | — |
| VUL-CVE-2014-8545 | — | MISS | — |
| VUL-CVE-2014-8546 | — | MISS | — |
| VUL-CVE-2014-8547 | — | MISS | — |
| VUL-CVE-2014-8548 | — | MISS | — |
| VUL-CVE-2014-8549 | — | MISS | — |
| VUL-CVE-2014-9130 | — | MISS | — |
| VUL-CVE-2014-9316 | — | MISS | — |
| VUL-CVE-2014-9317 | — | MISS | — |
| VUL-CVE-2014-9318 | — | MISS | — |
| VUL-CVE-2014-9319 | — | MISS | — |
| VUL-CVE-2014-9602 | — | MISS | — |
| VUL-CVE-2014-9603 | — | MISS | — |
| VUL-CVE-2014-9604 | — | MISS | — |
| VUL-CVE-2014-9656 | — | MISS | — |
| VUL-CVE-2014-9660 | — | MISS | — |
| VUL-CVE-2014-9661 | — | MISS | — |
| VUL-CVE-2014-9662 | — | MISS | — |
| VUL-CVE-2014-9663 | — | MISS | — |
| VUL-CVE-2014-9664 | — | MISS | — |
| VUL-CVE-2014-9665 | — | MISS | — |
| VUL-CVE-2014-9666 | — | MISS | — |
| VUL-CVE-2014-9669 | — | MISS | — |
| VUL-CVE-2014-9672 | — | MISS | — |
| VUL-CVE-2014-9675 | — | MISS | — |
| VUL-CVE-2014-9746 | — | MISS | — |
| VUL-CVE-2014-9747 | — | MISS | — |
| VUL-CVE-2015-0204 | — | MISS | — |
| VUL-CVE-2015-0205 | — | MISS | — |
| VUL-CVE-2015-0206 | — | MISS | — |
| VUL-CVE-2015-0278 | — | MISS | — |
| VUL-CVE-2015-1342 | — | MISS | — |
| VUL-CVE-2015-1344 | — | MISS | — |
| VUL-CVE-2015-1788 | — | MISS | — |
| VUL-CVE-2015-1789 | — | MISS | — |
| VUL-CVE-2015-1790 | — | MISS | — |
| VUL-CVE-2015-1791 | — | MISS | — |
| VUL-CVE-2015-1792 | — | MISS | — |
| VUL-CVE-2015-1872 | — | MISS | — |
| VUL-CVE-2015-2778 | — | MISS | — |
| VUL-CVE-2015-2779 | — | MISS | — |
| VUL-CVE-2015-3138 | — | MISS | — |
| VUL-CVE-2015-3238 | — | MISS | — |
| VUL-CVE-2015-3258 | — | MISS | — |
| VUL-CVE-2015-3395 | — | MISS | — |
| VUL-CVE-2015-3417 | — | MISS | — |
| VUL-CVE-2015-4470 | — | MISS | — |
| VUL-CVE-2015-4471 | — | MISS | — |
| VUL-CVE-2015-5194 | — | MISS | — |
| VUL-CVE-2015-5195 | — | MISS | — |
| VUL-CVE-2015-5219 | — | MISS | — |
| VUL-CVE-2015-6761 | — | MISS | — |
| VUL-CVE-2015-6818 | — | MISS | — |
| VUL-CVE-2015-6819 | — | MISS | — |
| VUL-CVE-2015-6820 | — | MISS | — |
| VUL-CVE-2015-6821 | — | MISS | — |
| VUL-CVE-2015-6822 | — | MISS | — |
| VUL-CVE-2015-6823 | — | MISS | — |
| VUL-CVE-2015-6824 | — | MISS | — |
| VUL-CVE-2015-6825 | — | MISS | — |
| VUL-CVE-2015-6826 | — | MISS | — |
| VUL-CVE-2015-8011 | — | MISS | — |
| VUL-CVE-2015-8012 | — | MISS | — |
| VUL-CVE-2015-8216 | — | MISS | — |
| VUL-CVE-2015-8217 | — | MISS | — |
| VUL-CVE-2015-8218 | — | MISS | — |
| VUL-CVE-2015-8219 | — | MISS | — |
| VUL-CVE-2015-8327 | — | MISS | — |
| VUL-CVE-2015-8364 | — | MISS | — |
| VUL-CVE-2015-8365 | — | MISS | — |
| VUL-CVE-2015-8547 | — | MISS | — |
| VUL-CVE-2015-8560 | — | MISS | — |
| VUL-CVE-2015-8661 | — | MISS | — |
| VUL-CVE-2015-8662 | — | MISS | — |
| VUL-CVE-2015-8663 | — | MISS | — |
| VUL-CVE-2015-8702 | — | MISS | — |
| VUL-CVE-2015-8789 | — | MISS | — |
| VUL-CVE-2015-8790 | — | MISS | — |
| VUL-CVE-2015-8791 | — | MISS | — |
| VUL-CVE-2015-8792 | — | MISS | — |
| VUL-CVE-2015-8871 | — | MISS | — |
| VUL-CVE-2015-8872 | — | MISS | — |
| VUL-CVE-2015-9059 | — | MISS | — |
| VUL-CVE-2015-9274 | — | MISS | — |
| VUL-CVE-2015-9381 | — | MISS | — |
| VUL-CVE-2015-9383 | — | MISS | — |
| VUL-CVE-2016-10156 | — | MISS | — |
| VUL-CVE-2016-10190 | — | MISS | — |
| VUL-CVE-2016-10191 | — | MISS | — |
| VUL-CVE-2016-10192 | — | MISS | — |
| VUL-CVE-2016-10210 | — | MISS | — |
| VUL-CVE-2016-10211 | — | MISS | — |
| VUL-CVE-2016-10328 | — | MISS | — |
| VUL-CVE-2016-10504 | — | MISS | — |
| VUL-CVE-2016-10506 | — | MISS | — |
| VUL-CVE-2016-10749 | — | MISS | — |
| VUL-CVE-2016-2180 | — | MISS | — |
| VUL-CVE-2016-2213 | — | MISS | — |
| VUL-CVE-2016-2326 | — | MISS | — |
| VUL-CVE-2016-2327 | — | MISS | — |
| VUL-CVE-2016-2328 | — | MISS | — |
| VUL-CVE-2016-2329 | — | MISS | — |
| VUL-CVE-2016-2330 | — | MISS | — |
| VUL-CVE-2016-3062 | — | MISS | — |
| VUL-CVE-2016-3183 | — | MISS | — |
| VUL-CVE-2016-3697 | — | MISS | — |
| VUL-CVE-2016-3698 | — | MISS | — |
| VUL-CVE-2016-4414 | — | MISS | — |
| VUL-CVE-2016-4796 | — | MISS | — |
| VUL-CVE-2016-4797 | — | MISS | — |
| VUL-CVE-2016-4804 | — | MISS | — |
| VUL-CVE-2016-5009 | — | MISS | — |
| VUL-CVE-2016-5104 | — | MISS | — |
| VUL-CVE-2016-5180 | — | MISS | — |
| VUL-CVE-2016-5350 | — | MISS | — |
| VUL-CVE-2016-5351 | — | MISS | — |
| VUL-CVE-2016-5352 | — | MISS | — |
| VUL-CVE-2016-5353 | — | MISS | — |
| VUL-CVE-2016-5354 | — | MISS | — |
| VUL-CVE-2016-5355 | — | MISS | — |
| VUL-CVE-2016-5356 | — | MISS | — |
| VUL-CVE-2016-5357 | — | MISS | — |
| VUL-CVE-2016-5358 | — | MISS | — |
| VUL-CVE-2016-5359 | — | MISS | — |
| VUL-CVE-2016-5361 | — | MISS | — |
| VUL-CVE-2016-6129 | — | MISS | — |
| VUL-CVE-2016-6164 | — | MISS | — |
| VUL-CVE-2016-6254 | — | MISS | — |
| VUL-CVE-2016-6671 | — | MISS | — |
| VUL-CVE-2016-6881 | — | MISS | — |
| VUL-CVE-2016-6920 | — | MISS | — |
| VUL-CVE-2016-7122 | — | MISS | — |
| VUL-CVE-2016-7141 | — | MISS | — |
| VUL-CVE-2016-7142 | — | MISS | — |
| VUL-CVE-2016-7163 | — | MISS | — |
| VUL-CVE-2016-7450 | — | MISS | — |
| VUL-CVE-2016-7502 | — | MISS | — |
| VUL-CVE-2016-7545 | — | MISS | — |
| VUL-CVE-2016-7555 | — | MISS | — |
| VUL-CVE-2016-7562 | — | MISS | — |
| VUL-CVE-2016-7785 | — | MISS | — |
| VUL-CVE-2016-7905 | — | MISS | — |
| VUL-CVE-2016-7969 | — | MISS | — |
| VUL-CVE-2016-8595 | — | MISS | — |
| VUL-CVE-2016-9113 | — | MISS | — |
| VUL-CVE-2016-9114 | — | MISS | — |
| VUL-CVE-2016-9264 | — | MISS | — |
| VUL-CVE-2016-9265 | — | MISS | — |
| VUL-CVE-2016-9266 | — | MISS | — |
| VUL-CVE-2016-9586 | — | MISS | — |
| VUL-CVE-2016-9840 | — | MISS | — |
| VUL-CVE-2016-9841 | — | MISS | — |
| VUL-CVE-2016-9842 | — | MISS | — |
| VUL-CVE-2016-9843 | — | MISS | — |
| VUL-CVE-2017-1000369 | — | MISS | — |
| VUL-CVE-2017-1000381 | — | MISS | — |
| VUL-CVE-2017-10965 | — | MISS | — |
| VUL-CVE-2017-10966 | — | MISS | — |
| VUL-CVE-2017-11328 | — | MISS | — |
| VUL-CVE-2017-11399 | — | MISS | — |
| VUL-CVE-2017-11423 | — | MISS | — |
| VUL-CVE-2017-11554 | — | MISS | — |
| VUL-CVE-2017-11555 | — | MISS | — |
| VUL-CVE-2017-11556 | — | MISS | — |
| VUL-CVE-2017-11608 | — | MISS | — |
| VUL-CVE-2017-11665 | — | MISS | — |
| VUL-CVE-2017-11719 | — | MISS | — |
| VUL-CVE-2017-11747 | — | MISS | — |
| VUL-CVE-2017-12424 | — | MISS | — |
| VUL-CVE-2017-12678 | — | MISS | — |
| VUL-CVE-2017-12858 | — | MISS | — |
| VUL-CVE-2017-12893 | — | MISS | — |
| VUL-CVE-2017-12894 | — | MISS | — |
| VUL-CVE-2017-12895 | — | MISS | — |
| VUL-CVE-2017-12898 | — | MISS | — |
| VUL-CVE-2017-12899 | — | MISS | — |
| VUL-CVE-2017-12901 | — | MISS | — |
| VUL-CVE-2017-12902 | — | MISS | — |
| VUL-CVE-2017-12963 | — | MISS | — |
| VUL-CVE-2017-12964 | — | MISS | — |
| VUL-CVE-2017-12982 | — | MISS | — |
| VUL-CVE-2017-12988 | — | MISS | — |
| VUL-CVE-2017-12989 | — | MISS | — |
| VUL-CVE-2017-12990 | — | MISS | — |
| VUL-CVE-2017-12991 | — | MISS | — |
| VUL-CVE-2017-12994 | — | MISS | — |
| VUL-CVE-2017-12996 | — | MISS | — |
| VUL-CVE-2017-12997 | — | MISS | — |
| VUL-CVE-2017-12998 | — | MISS | — |
| VUL-CVE-2017-12999 | — | MISS | — |
| VUL-CVE-2017-13001 | — | MISS | — |
| VUL-CVE-2017-13002 | — | MISS | — |
| VUL-CVE-2017-13003 | — | MISS | — |
| VUL-CVE-2017-13005 | — | MISS | — |
| VUL-CVE-2017-13006 | — | MISS | — |
| VUL-CVE-2017-13007 | — | MISS | — |
| VUL-CVE-2017-13010 | — | MISS | — |
| VUL-CVE-2017-13011 | — | MISS | — |
| VUL-CVE-2017-13012 | — | MISS | — |
| VUL-CVE-2017-13014 | — | MISS | — |
| VUL-CVE-2017-13015 | — | MISS | — |
| VUL-CVE-2017-13016 | — | MISS | — |
| VUL-CVE-2017-13017 | — | MISS | — |
| VUL-CVE-2017-13018 | — | MISS | — |
| VUL-CVE-2017-13019 | — | MISS | — |
| VUL-CVE-2017-13020 | — | MISS | — |
| VUL-CVE-2017-13021 | — | MISS | — |
| VUL-CVE-2017-13022 | — | MISS | — |
| VUL-CVE-2017-13023 | — | MISS | — |
| VUL-CVE-2017-13025 | — | MISS | — |
| VUL-CVE-2017-13026 | — | MISS | — |
| VUL-CVE-2017-13027 | — | MISS | — |
| VUL-CVE-2017-13028 | — | MISS | — |
| VUL-CVE-2017-13029 | — | MISS | — |
| VUL-CVE-2017-13030 | — | MISS | — |
| VUL-CVE-2017-13032 | — | MISS | — |
| VUL-CVE-2017-13033 | — | MISS | — |
| VUL-CVE-2017-13034 | — | MISS | — |
| VUL-CVE-2017-13035 | — | MISS | — |
| VUL-CVE-2017-13036 | — | MISS | — |
| VUL-CVE-2017-13037 | — | MISS | — |
| VUL-CVE-2017-13039 | — | MISS | — |
| VUL-CVE-2017-13040 | — | MISS | — |
| VUL-CVE-2017-13042 | — | MISS | — |
| VUL-CVE-2017-13043 | — | MISS | — |
| VUL-CVE-2017-13044 | — | MISS | — |
| VUL-CVE-2017-13045 | — | MISS | — |
| VUL-CVE-2017-13046 | — | MISS | — |
| VUL-CVE-2017-13047 | — | MISS | — |
| VUL-CVE-2017-13048 | — | MISS | — |
| VUL-CVE-2017-13050 | — | MISS | — |
| VUL-CVE-2017-13051 | — | MISS | — |
| VUL-CVE-2017-13052 | — | MISS | — |
| VUL-CVE-2017-13053 | — | MISS | — |
| VUL-CVE-2017-13054 | — | MISS | — |
| VUL-CVE-2017-13055 | — | MISS | — |
| VUL-CVE-2017-13083 | — | MISS | — |
| VUL-CVE-2017-13687 | — | MISS | — |
| VUL-CVE-2017-13688 | — | MISS | — |
| VUL-CVE-2017-13689 | — | MISS | — |
| VUL-CVE-2017-13690 | — | MISS | — |
| VUL-CVE-2017-13725 | — | MISS | — |
| VUL-CVE-2017-14032 | — | MISS | — |
| VUL-CVE-2017-14039 | — | MISS | — |
| VUL-CVE-2017-14040 | — | MISS | — |
| VUL-CVE-2017-14041 | — | MISS | — |
| VUL-CVE-2017-14054 | — | MISS | — |
| VUL-CVE-2017-14055 | — | MISS | — |
| VUL-CVE-2017-14056 | — | MISS | — |
| VUL-CVE-2017-14057 | — | MISS | — |
| VUL-CVE-2017-14058 | — | MISS | — |
| VUL-CVE-2017-14059 | — | MISS | — |
| VUL-CVE-2017-14107 | — | MISS | — |
| VUL-CVE-2017-14151 | — | MISS | — |
| VUL-CVE-2017-14152 | — | MISS | — |
| VUL-CVE-2017-14164 | — | MISS | — |
| VUL-CVE-2017-14169 | — | MISS | — |
| VUL-CVE-2017-14170 | — | MISS | — |
| VUL-CVE-2017-14171 | — | MISS | — |
| VUL-CVE-2017-14222 | — | MISS | — |
| VUL-CVE-2017-14223 | — | MISS | — |
| VUL-CVE-2017-14225 | — | MISS | — |
| VUL-CVE-2017-14749 | — | MISS | — |
| VUL-CVE-2017-14767 | — | MISS | — |
| VUL-CVE-2017-15672 | — | MISS | — |
| VUL-CVE-2017-15908 | — | MISS | — |
| VUL-CVE-2017-15924 | — | MISS | — |
| VUL-CVE-2017-16516 | — | MISS | — |
| VUL-CVE-2017-16818 | — | MISS | — |
| VUL-CVE-2017-16820 | — | MISS | — |
| VUL-CVE-2017-16840 | — | MISS | — |
| VUL-CVE-2017-16943 | — | MISS | — |
| VUL-CVE-2017-16944 | — | MISS | — |
| VUL-CVE-2017-17081 | — | MISS | — |
| VUL-CVE-2017-17479 | — | MISS | — |
| VUL-CVE-2017-17480 | — | MISS | — |
| VUL-CVE-2017-18078 | — | MISS | — |
| VUL-CVE-2017-18190 | — | MISS | — |
| VUL-CVE-2017-18212 | — | MISS | — |
| VUL-CVE-2017-18922 | — | MISS | — |
| VUL-CVE-2017-3730 | — | MISS | — |
| VUL-CVE-2017-3731 | — | MISS | — |
| VUL-CVE-2017-3732 | — | MISS | — |
| VUL-CVE-2017-3735 | — | MISS | — |
| VUL-CVE-2017-5522 | — | MISS | — |
| VUL-CVE-2017-5923 | — | MISS | — |
| VUL-CVE-2017-5924 | — | MISS | — |
| VUL-CVE-2017-6429 | — | MISS | — |
| VUL-CVE-2017-6888 | — | MISS | — |
| VUL-CVE-2017-7191 | — | MISS | — |
| VUL-CVE-2017-7407 | — | MISS | — |
| VUL-CVE-2017-7544 | — | MISS | — |
| VUL-CVE-2017-7578 | — | MISS | — |
| VUL-CVE-2017-7857 | — | MISS | — |
| VUL-CVE-2017-7858 | — | MISS | — |
| VUL-CVE-2017-7862 | — | MISS | — |
| VUL-CVE-2017-7863 | — | MISS | — |
| VUL-CVE-2017-7865 | — | MISS | — |
| VUL-CVE-2017-7866 | — | MISS | — |
| VUL-CVE-2017-8294 | — | MISS | — |
| VUL-CVE-2017-8855 | — | MISS | — |
| VUL-CVE-2017-8929 | — | MISS | — |
| VUL-CVE-2017-9217 | — | MISS | — |
| VUL-CVE-2017-9224 | — | MISS | — |
| VUL-CVE-2017-9225 | — | MISS | — |
| VUL-CVE-2017-9226 | — | MISS | — |
| VUL-CVE-2017-9227 | — | MISS | — |
| VUL-CVE-2017-9228 | — | MISS | — |
| VUL-CVE-2017-9229 | — | MISS | — |
| VUL-CVE-2017-9250 | — | MISS | — |
| VUL-CVE-2017-9304 | — | MISS | — |
| VUL-CVE-2017-9438 | — | MISS | — |
| VUL-CVE-2017-9465 | — | MISS | — |
| VUL-CVE-2017-9608 | — | MISS | — |
| VUL-CVE-2017-9831 | — | MISS | — |
| VUL-CVE-2017-9990 | — | MISS | — |
| VUL-CVE-2017-9991 | — | MISS | — |
| VUL-CVE-2017-9992 | — | MISS | — |
| VUL-CVE-2017-9993 | — | MISS | — |
| VUL-CVE-2017-9994 | — | MISS | — |
| VUL-CVE-2017-9995 | — | MISS | — |
| VUL-CVE-2017-9996 | — | MISS | — |
| VUL-CVE-2018-0488 | — | MISS | — |
| VUL-CVE-2018-0500 | — | MISS | — |
| VUL-CVE-2018-1000007 | — | MISS | — |
| VUL-CVE-2018-1000052 | — | MISS | — |
| VUL-CVE-2018-10001 | — | MISS | — |
| VUL-CVE-2018-1000120 | — | MISS | — |
| VUL-CVE-2018-1000121 | — | MISS | — |
| VUL-CVE-2018-1000122 | — | MISS | — |
| VUL-CVE-2018-1000178 | — | MISS | — |
| VUL-CVE-2018-1000179 | — | MISS | — |
| VUL-CVE-2018-1000300 | — | MISS | — |
| VUL-CVE-2018-1000301 | — | MISS | — |
| VUL-CVE-2018-10243 | — | MISS | — |
| VUL-CVE-2018-10756 | — | MISS | — |
| VUL-CVE-2018-1084 | — | MISS | — |
| VUL-CVE-2018-10861 | — | MISS | — |
| VUL-CVE-2018-1128 | — | MISS | — |
| VUL-CVE-2018-1129 | — | MISS | — |
| VUL-CVE-2018-11418 | — | MISS | — |
| VUL-CVE-2018-11419 | — | MISS | — |
| VUL-CVE-2018-11439 | — | MISS | — |
| VUL-CVE-2018-1152 | — | MISS | — |
| VUL-CVE-2018-11813 | — | MISS | — |
| VUL-CVE-2018-12436 | — | MISS | — |
| VUL-CVE-2018-12458 | — | MISS | — |
| VUL-CVE-2018-12459 | — | MISS | — |
| VUL-CVE-2018-12460 | — | MISS | — |
| VUL-CVE-2018-12684 | — | MISS | — |
| VUL-CVE-2018-12913 | — | MISS | — |
| VUL-CVE-2018-13112 | — | MISS | — |
| VUL-CVE-2018-13300 | — | MISS | — |
| VUL-CVE-2018-13301 | — | MISS | — |
| VUL-CVE-2018-13302 | — | MISS | — |
| VUL-CVE-2018-13303 | — | MISS | — |
| VUL-CVE-2018-13304 | — | MISS | — |
| VUL-CVE-2018-13305 | — | MISS | — |
| VUL-CVE-2018-13785 | — | MISS | — |
| VUL-CVE-2018-14394 | — | MISS | — |
| VUL-CVE-2018-14395 | — | MISS | — |
| VUL-CVE-2018-14461 | — | MISS | — |
| VUL-CVE-2018-14462 | — | MISS | — |
| VUL-CVE-2018-14463 | — | MISS | — |
| VUL-CVE-2018-14464 | — | MISS | — |
| VUL-CVE-2018-14465 | — | MISS | — |
| VUL-CVE-2018-14466 | — | MISS | — |
| VUL-CVE-2018-14467 | — | MISS | — |
| VUL-CVE-2018-14468 | — | MISS | — |
| VUL-CVE-2018-14469 | — | MISS | — |
| VUL-CVE-2018-14470 | — | MISS | — |
| VUL-CVE-2018-14498 | — | MISS | — |
| VUL-CVE-2018-14660 | — | MISS | — |
| VUL-CVE-2018-14679 | — | MISS | — |
| VUL-CVE-2018-14680 | — | MISS | — |
| VUL-CVE-2018-14681 | — | MISS | — |
| VUL-CVE-2018-14879 | — | MISS | — |
| VUL-CVE-2018-14880 | — | MISS | — |
| VUL-CVE-2018-14881 | — | MISS | — |
| VUL-CVE-2018-15822 | — | MISS | — |
| VUL-CVE-2018-16228 | — | MISS | — |
| VUL-CVE-2018-16229 | — | MISS | — |
| VUL-CVE-2018-16230 | — | MISS | — |
| VUL-CVE-2018-16300 | — | MISS | — |
| VUL-CVE-2018-16301 | — | MISS | — |
| VUL-CVE-2018-16393 | — | MISS | — |
| VUL-CVE-2018-16451 | — | MISS | — |
| VUL-CVE-2018-16452 | — | MISS | — |
| VUL-CVE-2018-16839 | — | MISS | — |
| VUL-CVE-2018-16840 | — | MISS | — |
| VUL-CVE-2018-16842 | — | MISS | — |
| VUL-CVE-2018-17336 | — | MISS | — |
| VUL-CVE-2018-18584 | — | MISS | — |
| VUL-CVE-2018-18585 | — | MISS | — |
| VUL-CVE-2018-18586 | — | MISS | — |
| VUL-CVE-2018-18836 | — | MISS | — |
| VUL-CVE-2018-18837 | — | MISS | — |
| VUL-CVE-2018-18838 | — | MISS | — |
| VUL-CVE-2018-18839 | — | MISS | — |
| VUL-CVE-2018-19044 | — | MISS | — |
| VUL-CVE-2018-19045 | — | MISS | — |
| VUL-CVE-2018-19093 | — | MISS | — |
| VUL-CVE-2018-19219 | — | MISS | — |
| VUL-CVE-2018-19664 | — | MISS | — |
| VUL-CVE-2018-19837 | — | MISS | — |
| VUL-CVE-2018-19974 | — | MISS | — |
| VUL-CVE-2018-1999010 | — | MISS | — |
| VUL-CVE-2018-1999011 | — | MISS | — |
| VUL-CVE-2018-1999012 | — | MISS | — |
| VUL-CVE-2018-1999013 | — | MISS | — |
| VUL-CVE-2018-1999014 | — | MISS | — |
| VUL-CVE-2018-1999015 | — | MISS | — |
| VUL-CVE-2018-20030 | — | MISS | — |
| VUL-CVE-2018-20145 | — | MISS | — |
| VUL-CVE-2018-20330 | — | MISS | — |
| VUL-CVE-2018-20749 | — | MISS | — |
| VUL-CVE-2018-20750 | — | MISS | — |
| VUL-CVE-2018-20839 | — | MISS | — |
| VUL-CVE-2018-20847 | — | MISS | — |
| VUL-CVE-2018-21010 | — | MISS | — |
| VUL-CVE-2018-21233 | — | MISS | — |
| VUL-CVE-2018-21247 | — | MISS | — |
| VUL-CVE-2018-25032 | — | MISS | — |
| VUL-CVE-2018-5727 | — | MISS | — |
| VUL-CVE-2018-6337 | — | MISS | — |
| VUL-CVE-2018-6392 | — | MISS | — |
| VUL-CVE-2018-6616 | — | MISS | — |
| VUL-CVE-2018-6621 | — | MISS | — |
| VUL-CVE-2018-6789 | — | MISS | — |
| VUL-CVE-2018-6912 | — | MISS | — |
| VUL-CVE-2018-6942 | — | MISS | — |
| VUL-CVE-2018-7557 | — | MISS | — |
| VUL-CVE-2018-7648 | — | MISS | — |
| VUL-CVE-2018-7751 | — | MISS | — |
| VUL-CVE-2018-8784 | — | MISS | — |
| VUL-CVE-2018-8785 | — | MISS | — |
| VUL-CVE-2018-8786 | — | MISS | — |
| VUL-CVE-2018-8787 | — | MISS | — |
| VUL-CVE-2018-8788 | — | MISS | — |
| VUL-CVE-2018-8789 | — | MISS | — |
| VUL-CVE-2018-9841 | — | MISS | — |
| VUL-CVE-2019-1000016 | — | MISS | — |
| VUL-CVE-2019-1010239 | — | MISS | — |
| VUL-CVE-2019-1010305 | — | MISS | — |
| VUL-CVE-2019-10664 | — | MISS | — |
| VUL-CVE-2019-10678 | — | MISS | — |
| VUL-CVE-2019-11338 | — | MISS | — |
| VUL-CVE-2019-11339 | — | MISS | — |
| VUL-CVE-2019-11411 | — | MISS | — |
| VUL-CVE-2019-11412 | — | MISS | — |
| VUL-CVE-2019-11413 | — | MISS | — |
| VUL-CVE-2019-11934 | — | MISS | — |
| VUL-CVE-2019-12730 | — | MISS | — |
| VUL-CVE-2019-12973 | — | MISS | — |
| VUL-CVE-2019-12980 | — | MISS | — |
| VUL-CVE-2019-12981 | — | MISS | — |
| VUL-CVE-2019-12982 | — | MISS | — |
| VUL-CVE-2019-13045 | — | MISS | — |
| VUL-CVE-2019-13115 | — | MISS | — |
| VUL-CVE-2019-13225 | — | MISS | — |
| VUL-CVE-2019-13312 | — | MISS | — |
| VUL-CVE-2019-13390 | — | MISS | — |
| VUL-CVE-2019-14459 | — | MISS | — |
| VUL-CVE-2019-14462 | — | MISS | — |
| VUL-CVE-2019-14463 | — | MISS | — |
| VUL-CVE-2019-15161 | — | MISS | — |
| VUL-CVE-2019-15162 | — | MISS | — |
| VUL-CVE-2019-15163 | — | MISS | — |
| VUL-CVE-2019-15164 | — | MISS | — |
| VUL-CVE-2019-15165 | — | MISS | — |
| VUL-CVE-2019-15166 | — | MISS | — |
| VUL-CVE-2019-15167 | — | MISS | — |
| VUL-CVE-2019-15651 | — | MISS | — |
| VUL-CVE-2019-15900 | — | MISS | — |
| VUL-CVE-2019-15901 | — | MISS | — |
| VUL-CVE-2019-15942 | — | MISS | — |
| VUL-CVE-2019-15945 | — | MISS | — |
| VUL-CVE-2019-15946 | — | MISS | — |
| VUL-CVE-2019-16163 | — | MISS | — |
| VUL-CVE-2019-16748 | — | MISS | — |
| VUL-CVE-2019-16778 | — | MISS | — |
| VUL-CVE-2019-17177 | — | MISS | — |
| VUL-CVE-2019-17178 | — | MISS | — |
| VUL-CVE-2019-17498 | — | MISS | — |
| VUL-CVE-2019-17533 | — | MISS | — |
| VUL-CVE-2019-17534 | — | MISS | — |
| VUL-CVE-2019-17539 | — | MISS | — |
| VUL-CVE-2019-17542 | — | MISS | — |
| VUL-CVE-2019-17582 | — | MISS | — |
| VUL-CVE-2019-18397 | — | MISS | — |
| VUL-CVE-2019-19012 | — | MISS | — |
| VUL-CVE-2019-19246 | — | MISS | — |
| VUL-CVE-2019-19333 | — | MISS | — |
| VUL-CVE-2019-19334 | — | MISS | — |
| VUL-CVE-2019-19479 | — | MISS | — |
| VUL-CVE-2019-19480 | — | MISS | — |
| VUL-CVE-2019-19481 | — | MISS | — |
| VUL-CVE-2019-19648 | — | MISS | — |
| VUL-CVE-2019-19795 | — | MISS | — |
| VUL-CVE-2019-19882 | — | MISS | — |
| VUL-CVE-2019-19931 | — | MISS | — |
| VUL-CVE-2019-19944 | — | MISS | — |
| VUL-CVE-2019-19957 | — | MISS | — |
| VUL-CVE-2019-19960 | — | MISS | — |
| VUL-CVE-2019-19962 | — | MISS | — |
| VUL-CVE-2019-19963 | — | MISS | — |
| VUL-CVE-2019-20017 | — | MISS | — |
| VUL-CVE-2019-20018 | — | MISS | — |
| VUL-CVE-2019-20019 | — | MISS | — |
| VUL-CVE-2019-20020 | — | MISS | — |
| VUL-CVE-2019-20052 | — | MISS | — |
| VUL-CVE-2019-20386 | — | MISS | — |
| VUL-CVE-2019-20387 | — | MISS | — |
| VUL-CVE-2019-20391 | — | MISS | — |
| VUL-CVE-2019-20392 | — | MISS | — |
| VUL-CVE-2019-20393 | — | MISS | — |
| VUL-CVE-2019-20394 | — | MISS | — |
| VUL-CVE-2019-20395 | — | MISS | — |
| VUL-CVE-2019-20396 | — | MISS | — |
| VUL-CVE-2019-20397 | — | MISS | — |
| VUL-CVE-2019-20398 | — | MISS | — |
| VUL-CVE-2019-20788 | — | MISS | — |
| VUL-CVE-2019-20791 | — | MISS | — |
| VUL-CVE-2019-20792 | — | MISS | — |
| VUL-CVE-2019-20839 | — | MISS | — |
| VUL-CVE-2019-20840 | — | MISS | — |
| VUL-CVE-2019-20917 | — | MISS | — |
| VUL-CVE-2019-20918 | — | MISS | — |
| VUL-CVE-2019-25016 | — | MISS | — |
| VUL-CVE-2019-3554 | — | MISS | — |
| VUL-CVE-2019-3563 | — | MISS | — |
| VUL-CVE-2019-3804 | — | MISS | — |
| VUL-CVE-2019-5482 | — | MISS | — |
| VUL-CVE-2019-5736 | — | MISS | — |
| VUL-CVE-2019-6454 | — | MISS | — |
| VUL-CVE-2019-6706 | — | MISS | — |
| VUL-CVE-2019-6976 | — | MISS | — |
| VUL-CVE-2019-8359 | — | MISS | — |
| VUL-CVE-2019-8376 | — | MISS | — |
| VUL-CVE-2019-8377 | — | MISS | — |
| VUL-CVE-2019-8381 | — | MISS | — |
| VUL-CVE-2019-9026 | — | MISS | — |
| VUL-CVE-2019-9027 | — | MISS | — |
| VUL-CVE-2019-9028 | — | MISS | — |
| VUL-CVE-2019-9029 | — | MISS | — |
| VUL-CVE-2019-9030 | — | MISS | — |
| VUL-CVE-2019-9032 | — | MISS | — |
| VUL-CVE-2019-9033 | — | MISS | — |
| VUL-CVE-2019-9034 | — | MISS | — |
| VUL-CVE-2019-9035 | — | MISS | — |
| VUL-CVE-2019-9036 | — | MISS | — |
| VUL-CVE-2019-9037 | — | MISS | — |
| VUL-CVE-2019-9038 | — | MISS | — |
| VUL-CVE-2019-9183 | — | MISS | — |
| VUL-CVE-2019-9718 | — | MISS | — |
| VUL-CVE-2019-9721 | — | MISS | — |
| VUL-CVE-2020-10932 | — | MISS | — |
| VUL-CVE-2020-11042 | — | MISS | — |
| VUL-CVE-2020-11044 | — | MISS | — |
| VUL-CVE-2020-11045 | — | MISS | — |
| VUL-CVE-2020-11046 | — | MISS | — |
| VUL-CVE-2020-11047 | — | MISS | — |
| VUL-CVE-2020-11048 | — | MISS | — |
| VUL-CVE-2020-11049 | — | MISS | — |
| VUL-CVE-2020-11058 | — | MISS | — |
| VUL-CVE-2020-11068 | — | MISS | — |
| VUL-CVE-2020-11080 | — | MISS | — |
| VUL-CVE-2020-11085 | — | MISS | — |
| VUL-CVE-2020-11086 | — | MISS | — |
| VUL-CVE-2020-11087 | — | MISS | — |
| VUL-CVE-2020-11088 | — | MISS | — |
| VUL-CVE-2020-11089 | — | MISS | — |
| VUL-CVE-2020-11095 | — | MISS | — |
| VUL-CVE-2020-11096 | — | MISS | — |
| VUL-CVE-2020-11097 | — | MISS | — |
| VUL-CVE-2020-11098 | — | MISS | — |
| VUL-CVE-2020-11099 | — | MISS | — |
| VUL-CVE-2020-11526 | — | MISS | — |
| VUL-CVE-2020-11735 | — | MISS | — |
| VUL-CVE-2020-11939 | — | MISS | — |
| VUL-CVE-2020-11940 | — | MISS | — |
| VUL-CVE-2020-11958 | — | MISS | — |
| VUL-CVE-2020-12284 | — | MISS | — |
| VUL-CVE-2020-12740 | — | MISS | — |
| VUL-CVE-2020-13112 | — | MISS | — |
| VUL-CVE-2020-13113 | — | MISS | — |
| VUL-CVE-2020-13114 | — | MISS | — |
| VUL-CVE-2020-13396 | — | MISS | — |
| VUL-CVE-2020-13397 | — | MISS | — |
| VUL-CVE-2020-13398 | — | MISS | — |
| VUL-CVE-2020-13649 | — | MISS | — |
| VUL-CVE-2020-13790 | — | MISS | — |
| VUL-CVE-2020-13904 | — | MISS | — |
| VUL-CVE-2020-13984 | — | MISS | — |
| VUL-CVE-2020-13985 | — | MISS | — |
| VUL-CVE-2020-14163 | — | MISS | — |
| VUL-CVE-2020-14212 | — | MISS | — |
| VUL-CVE-2020-14354 | — | MISS | — |
| VUL-CVE-2020-14396 | — | MISS | — |
| VUL-CVE-2020-14397 | — | MISS | — |
| VUL-CVE-2020-14398 | — | MISS | — |
| VUL-CVE-2020-14399 | — | MISS | — |
| VUL-CVE-2020-14400 | — | MISS | — |
| VUL-CVE-2020-14401 | — | MISS | — |
| VUL-CVE-2020-14402 | — | MISS | — |
| VUL-CVE-2020-14403 | — | MISS | — |
| VUL-CVE-2020-14404 | — | MISS | — |
| VUL-CVE-2020-14405 | — | MISS | — |
| VUL-CVE-2020-15158 | — | MISS | — |
| VUL-CVE-2020-15190 | — | MISS | — |
| VUL-CVE-2020-15191 | — | MISS | — |
| VUL-CVE-2020-15192 | — | MISS | — |
| VUL-CVE-2020-15193 | — | MISS | — |
| VUL-CVE-2020-15194 | — | MISS | — |
| VUL-CVE-2020-15195 | — | MISS | — |
| VUL-CVE-2020-15196 | — | MISS | — |
| VUL-CVE-2020-15197 | — | MISS | — |
| VUL-CVE-2020-15198 | — | MISS | — |
| VUL-CVE-2020-15199 | — | MISS | — |
| VUL-CVE-2020-15200 | — | MISS | — |
| VUL-CVE-2020-15201 | — | MISS | — |
| VUL-CVE-2020-15202 | — | MISS | — |
| VUL-CVE-2020-15203 | — | MISS | — |
| VUL-CVE-2020-15204 | — | MISS | — |
| VUL-CVE-2020-15205 | — | MISS | — |
| VUL-CVE-2020-15206 | — | MISS | — |
| VUL-CVE-2020-15207 | — | MISS | — |
| VUL-CVE-2020-15208 | — | MISS | — |
| VUL-CVE-2020-15209 | — | MISS | — |
| VUL-CVE-2020-15210 | — | MISS | — |
| VUL-CVE-2020-15211 | — | MISS | — |
| VUL-CVE-2020-15212 | — | MISS | — |
| VUL-CVE-2020-15213 | — | MISS | — |
| VUL-CVE-2020-15214 | — | MISS | — |
| VUL-CVE-2020-15257 | — | MISS | — |
| VUL-CVE-2020-15265 | — | MISS | — |
| VUL-CVE-2020-15266 | — | MISS | — |
| VUL-CVE-2020-15471 | — | MISS | — |
| VUL-CVE-2020-15472 | — | MISS | — |
| VUL-CVE-2020-15473 | — | MISS | — |
| VUL-CVE-2020-15474 | — | MISS | — |
| VUL-CVE-2020-15475 | — | MISS | — |
| VUL-CVE-2020-15476 | — | MISS | — |
| VUL-CVE-2020-15888 | — | MISS | — |
| VUL-CVE-2020-15889 | — | MISS | — |
| VUL-CVE-2020-15945 | — | MISS | — |
| VUL-CVE-2020-16150 | — | MISS | — |
| VUL-CVE-2020-1712 | — | MISS | — |
| VUL-CVE-2020-17437 | — | MISS | — |
| VUL-CVE-2020-1763 | — | MISS | — |
| VUL-CVE-2020-18976 | — | MISS | — |
| VUL-CVE-2020-19497 | — | MISS | — |
| VUL-CVE-2020-20276 | — | MISS | — |
| VUL-CVE-2020-20277 | — | MISS | — |
| VUL-CVE-2020-20446 | — | MISS | — |
| VUL-CVE-2020-20448 | — | MISS | — |
| VUL-CVE-2020-20450 | — | MISS | — |
| VUL-CVE-2020-20451 | — | MISS | — |
| VUL-CVE-2020-20453 | — | MISS | — |
| VUL-CVE-2020-20739 | — | MISS | — |
| VUL-CVE-2020-20891 | — | MISS | — |
| VUL-CVE-2020-20892 | — | MISS | — |
| VUL-CVE-2020-20896 | — | MISS | — |
| VUL-CVE-2020-20898 | — | MISS | — |
| VUL-CVE-2020-20902 | — | MISS | — |
| VUL-CVE-2020-21041 | — | MISS | — |
| VUL-CVE-2020-21605 | — | MISS | — |
| VUL-CVE-2020-22015 | — | MISS | — |
| VUL-CVE-2020-22016 | — | MISS | — |
| VUL-CVE-2020-22017 | — | MISS | — |
| VUL-CVE-2020-22019 | — | MISS | — |
| VUL-CVE-2020-22020 | — | MISS | — |
| VUL-CVE-2020-22021 | — | MISS | — |
| VUL-CVE-2020-22022 | — | MISS | — |
| VUL-CVE-2020-22023 | — | MISS | — |
| VUL-CVE-2020-22024 | — | MISS | — |
| VUL-CVE-2020-22025 | — | MISS | — |
| VUL-CVE-2020-22026 | — | MISS | — |
| VUL-CVE-2020-22027 | — | MISS | — |
| VUL-CVE-2020-22028 | — | MISS | — |
| VUL-CVE-2020-22029 | — | MISS | — |
| VUL-CVE-2020-22030 | — | MISS | — |
| VUL-CVE-2020-22031 | — | MISS | — |
| VUL-CVE-2020-22032 | — | MISS | — |
| VUL-CVE-2020-22034 | — | MISS | — |
| VUL-CVE-2020-22035 | — | MISS | — |
| VUL-CVE-2020-22036 | — | MISS | — |
| VUL-CVE-2020-22037 | — | MISS | — |
| VUL-CVE-2020-22038 | — | MISS | — |
| VUL-CVE-2020-22039 | — | MISS | — |
| VUL-CVE-2020-22040 | — | MISS | — |
| VUL-CVE-2020-22041 | — | MISS | — |
| VUL-CVE-2020-22042 | — | MISS | — |
| VUL-CVE-2020-22043 | — | MISS | — |
| VUL-CVE-2020-22044 | — | MISS | — |
| VUL-CVE-2020-22046 | — | MISS | — |
| VUL-CVE-2020-22048 | — | MISS | — |
| VUL-CVE-2020-22217 | — | MISS | — |
| VUL-CVE-2020-22284 | — | MISS | — |
| VUL-CVE-2020-23273 | — | MISS | — |
| VUL-CVE-2020-23306 | — | MISS | — |
| VUL-CVE-2020-23309 | — | MISS | — |
| VUL-CVE-2020-23310 | — | MISS | — |
| VUL-CVE-2020-23313 | — | MISS | — |
| VUL-CVE-2020-23314 | — | MISS | — |
| VUL-CVE-2020-23319 | — | MISS | — |
| VUL-CVE-2020-23320 | — | MISS | — |
| VUL-CVE-2020-23323 | — | MISS | — |
| VUL-CVE-2020-24020 | — | MISS | — |
| VUL-CVE-2020-24074 | — | MISS | — |
| VUL-CVE-2020-24266 | — | MISS | — |
| VUL-CVE-2020-24342 | — | MISS | — |
| VUL-CVE-2020-24344 | — | MISS | — |
| VUL-CVE-2020-24369 | — | MISS | — |
| VUL-CVE-2020-24370 | — | MISS | — |
| VUL-CVE-2020-24371 | — | MISS | — |
| VUL-CVE-2020-24994 | — | MISS | — |
| VUL-CVE-2020-26243 | — | MISS | — |
| VUL-CVE-2020-26262 | — | MISS | — |
| VUL-CVE-2020-26266 | — | MISS | — |
| VUL-CVE-2020-26267 | — | MISS | — |
| VUL-CVE-2020-26268 | — | MISS | — |
| VUL-CVE-2020-26269 | — | MISS | — |
| VUL-CVE-2020-26270 | — | MISS | — |
| VUL-CVE-2020-26271 | — | MISS | — |
| VUL-CVE-2020-26570 | — | MISS | — |
| VUL-CVE-2020-26572 | — | MISS | — |
| VUL-CVE-2020-27153 | — | MISS | — |
| VUL-CVE-2020-27209 | — | MISS | — |
| VUL-CVE-2020-27347 | — | MISS | — |
| VUL-CVE-2020-27638 | — | MISS | — |
| VUL-CVE-2020-28840 | — | MISS | — |
| VUL-CVE-2020-29363 | — | MISS | — |
| VUL-CVE-2020-29367 | — | MISS | — |
| VUL-CVE-2020-29657 | — | MISS | — |
| VUL-CVE-2020-35538 | — | MISS | — |
| VUL-CVE-2020-35605 | — | MISS | — |
| VUL-CVE-2020-35964 | — | MISS | — |
| VUL-CVE-2020-35965 | — | MISS | — |
| VUL-CVE-2020-36138 | — | MISS | — |
| VUL-CVE-2020-36177 | — | MISS | — |
| VUL-CVE-2020-36315 | — | MISS | — |
| VUL-CVE-2020-36316 | — | MISS | — |
| VUL-CVE-2020-36330 | — | MISS | — |
| VUL-CVE-2020-36400 | — | MISS | — |
| VUL-CVE-2020-36422 | — | MISS | — |
| VUL-CVE-2020-36425 | — | MISS | — |
| VUL-CVE-2020-36426 | — | MISS | — |
| VUL-CVE-2020-36429 | — | MISS | — |
| VUL-CVE-2020-36430 | — | MISS | — |
| VUL-CVE-2020-36475 | — | MISS | — |
| VUL-CVE-2020-36476 | — | MISS | — |
| VUL-CVE-2020-36477 | — | MISS | — |
| VUL-CVE-2020-36478 | — | MISS | — |
| VUL-CVE-2020-4030 | — | MISS | — |
| VUL-CVE-2020-4031 | — | MISS | — |
| VUL-CVE-2020-4032 | — | MISS | — |
| VUL-CVE-2020-4033 | — | MISS | — |
| VUL-CVE-2020-4044 | — | MISS | — |
| VUL-CVE-2020-5204 | — | MISS | — |
| VUL-CVE-2020-5208 | — | MISS | — |
| VUL-CVE-2020-5215 | — | MISS | — |
| VUL-CVE-2020-5221 | — | MISS | — |
| VUL-CVE-2020-5235 | — | MISS | — |
| VUL-CVE-2020-7042 | — | MISS | — |
| VUL-CVE-2020-7043 | — | MISS | — |
| VUL-CVE-2020-8036 | — | MISS | — |
| VUL-CVE-2020-8037 | — | MISS | — |
| VUL-CVE-2020-8169 | — | MISS | — |
| VUL-CVE-2020-8177 | — | MISS | — |
| VUL-CVE-2020-8231 | — | MISS | — |
| VUL-CVE-2020-8277 | — | MISS | — |
| VUL-CVE-2020-8284 | — | MISS | — |
| VUL-CVE-2020-8285 | — | MISS | — |
| VUL-CVE-2020-9432 | — | MISS | — |
| VUL-CVE-2020-9433 | — | MISS | — |
| VUL-CVE-2020-9434 | — | MISS | — |
| VUL-CVE-2021-21330 | — | MISS | — |
| VUL-CVE-2021-21334 | — | MISS | — |
| VUL-CVE-2021-21401 | — | MISS | — |
| VUL-CVE-2021-21404 | — | MISS | — |
| VUL-CVE-2021-21410 | — | MISS | — |
| VUL-CVE-2021-22876 | — | MISS | — |
| VUL-CVE-2021-22890 | — | MISS | — |
| VUL-CVE-2021-22897 | — | MISS | — |
| VUL-CVE-2021-22898 | — | MISS | — |
| VUL-CVE-2021-22901 | — | MISS | — |
| VUL-CVE-2021-22924 | — | MISS | — |
| VUL-CVE-2021-22925 | — | MISS | — |
| VUL-CVE-2021-22946 | — | MISS | — |
| VUL-CVE-2021-22947 | — | MISS | — |
| VUL-CVE-2021-23520 | — | MISS | — |
| VUL-CVE-2021-24036 | — | MISS | — |
| VUL-CVE-2021-26567 | — | MISS | — |
| VUL-CVE-2021-27097 | — | MISS | — |
| VUL-CVE-2021-27138 | — | MISS | — |
| VUL-CVE-2021-28166 | — | MISS | — |
| VUL-CVE-2021-28904 | — | MISS | — |
| VUL-CVE-2021-28905 | — | MISS | — |
| VUL-CVE-2021-29390 | — | MISS | — |
| VUL-CVE-2021-29512 | — | MISS | — |
| VUL-CVE-2021-29513 | — | MISS | — |
| VUL-CVE-2021-29514 | — | MISS | — |
| VUL-CVE-2021-29515 | — | MISS | — |
| VUL-CVE-2021-29516 | — | MISS | — |
| VUL-CVE-2021-29517 | — | MISS | — |
| VUL-CVE-2021-29518 | — | MISS | — |
| VUL-CVE-2021-29519 | — | MISS | — |
| VUL-CVE-2021-29520 | — | MISS | — |
| VUL-CVE-2021-29521 | — | MISS | — |
| VUL-CVE-2021-29522 | — | MISS | — |
| VUL-CVE-2021-29523 | — | MISS | — |
| VUL-CVE-2021-29524 | — | MISS | — |
| VUL-CVE-2021-29525 | — | MISS | — |
| VUL-CVE-2021-29526 | — | MISS | — |
| VUL-CVE-2021-29527 | — | MISS | — |
| VUL-CVE-2021-29528 | — | MISS | — |
| VUL-CVE-2021-29529 | — | MISS | — |
| VUL-CVE-2021-29530 | — | MISS | — |
| VUL-CVE-2021-29531 | — | MISS | — |
| VUL-CVE-2021-29532 | — | MISS | — |
| VUL-CVE-2021-29533 | — | MISS | — |
| VUL-CVE-2021-29534 | — | MISS | — |
| VUL-CVE-2021-29535 | — | MISS | — |
| VUL-CVE-2021-29536 | — | MISS | — |
| VUL-CVE-2021-29537 | — | MISS | — |
| VUL-CVE-2021-29538 | — | MISS | — |
| VUL-CVE-2021-29539 | — | MISS | — |
| VUL-CVE-2021-29540 | — | MISS | — |
| VUL-CVE-2021-29541 | — | MISS | — |
| VUL-CVE-2021-29542 | — | MISS | — |
| VUL-CVE-2021-29543 | — | MISS | — |
| VUL-CVE-2021-29544 | — | MISS | — |
| VUL-CVE-2021-29545 | — | MISS | — |
| VUL-CVE-2021-29546 | — | MISS | — |
| VUL-CVE-2021-29547 | — | MISS | — |
| VUL-CVE-2021-29548 | — | MISS | — |
| VUL-CVE-2021-29549 | — | MISS | — |
| VUL-CVE-2021-29550 | — | MISS | — |
| VUL-CVE-2021-29551 | — | MISS | — |
| VUL-CVE-2021-29552 | — | MISS | — |
| VUL-CVE-2021-29553 | — | MISS | — |
| VUL-CVE-2021-29554 | — | MISS | — |
| VUL-CVE-2021-29555 | — | MISS | — |
| VUL-CVE-2021-29556 | — | MISS | — |
| VUL-CVE-2021-29557 | — | MISS | — |
| VUL-CVE-2021-29558 | — | MISS | — |
| VUL-CVE-2021-29559 | — | MISS | — |
| VUL-CVE-2021-29560 | — | MISS | — |
| VUL-CVE-2021-29561 | — | MISS | — |
| VUL-CVE-2021-29562 | — | MISS | — |
| VUL-CVE-2021-29563 | — | MISS | — |
| VUL-CVE-2021-29564 | — | MISS | — |
| VUL-CVE-2021-29565 | — | MISS | — |
| VUL-CVE-2021-29566 | — | MISS | — |
| VUL-CVE-2021-29567 | — | MISS | — |
| VUL-CVE-2021-29568 | — | MISS | — |
| VUL-CVE-2021-29569 | — | MISS | — |
| VUL-CVE-2021-29570 | — | MISS | — |
| VUL-CVE-2021-29571 | — | MISS | — |
| VUL-CVE-2021-29572 | — | MISS | — |
| VUL-CVE-2021-29573 | — | MISS | — |
| VUL-CVE-2021-29574 | — | MISS | — |
| VUL-CVE-2021-29575 | — | MISS | — |
| VUL-CVE-2021-29576 | — | MISS | — |
| VUL-CVE-2021-29577 | — | MISS | — |
| VUL-CVE-2021-29578 | — | MISS | — |
| VUL-CVE-2021-29579 | — | MISS | — |
| VUL-CVE-2021-29580 | — | MISS | — |
| VUL-CVE-2021-29581 | — | MISS | — |
| VUL-CVE-2021-29582 | — | MISS | — |
| VUL-CVE-2021-29583 | — | MISS | — |
| VUL-CVE-2021-29584 | — | MISS | — |
| VUL-CVE-2021-29585 | — | MISS | — |
| VUL-CVE-2021-29586 | — | MISS | — |
| VUL-CVE-2021-29587 | — | MISS | — |
| VUL-CVE-2021-29588 | — | MISS | — |
| VUL-CVE-2021-29589 | — | MISS | — |
| VUL-CVE-2021-29590 | — | MISS | — |
| VUL-CVE-2021-29591 | — | MISS | — |
| VUL-CVE-2021-29592 | — | MISS | — |
| VUL-CVE-2021-29593 | — | MISS | — |
| VUL-CVE-2021-29594 | — | MISS | — |
| VUL-CVE-2021-29595 | — | MISS | — |
| VUL-CVE-2021-29596 | — | MISS | — |
| VUL-CVE-2021-29597 | — | MISS | — |
| VUL-CVE-2021-29598 | — | MISS | — |
| VUL-CVE-2021-29599 | — | MISS | — |
| VUL-CVE-2021-29600 | — | MISS | — |
| VUL-CVE-2021-29601 | — | MISS | — |
| VUL-CVE-2021-29602 | — | MISS | — |
| VUL-CVE-2021-29603 | — | MISS | — |
| VUL-CVE-2021-29604 | — | MISS | — |
| VUL-CVE-2021-29605 | — | MISS | — |
| VUL-CVE-2021-29606 | — | MISS | — |
| VUL-CVE-2021-29607 | — | MISS | — |
| VUL-CVE-2021-29608 | — | MISS | — |
| VUL-CVE-2021-29610 | — | MISS | — |
| VUL-CVE-2021-29611 | — | MISS | — |
| VUL-CVE-2021-29612 | — | MISS | — |
| VUL-CVE-2021-29613 | — | MISS | — |
| VUL-CVE-2021-29614 | — | MISS | — |
| VUL-CVE-2021-29615 | — | MISS | — |
| VUL-CVE-2021-29616 | — | MISS | — |
| VUL-CVE-2021-29617 | — | MISS | — |
| VUL-CVE-2021-29618 | — | MISS | — |
| VUL-CVE-2021-29619 | — | MISS | — |
| VUL-CVE-2021-30123 | — | MISS | — |
| VUL-CVE-2021-30218 | — | MISS | — |
| VUL-CVE-2021-30219 | — | MISS | — |
| VUL-CVE-2021-30465 | — | MISS | — |
| VUL-CVE-2021-31660 | — | MISS | — |
| VUL-CVE-2021-31661 | — | MISS | — |
| VUL-CVE-2021-31662 | — | MISS | — |
| VUL-CVE-2021-31663 | — | MISS | — |
| VUL-CVE-2021-31664 | — | MISS | — |
| VUL-CVE-2021-32272 | — | MISS | — |
| VUL-CVE-2021-32273 | — | MISS | — |
| VUL-CVE-2021-32276 | — | MISS | — |
| VUL-CVE-2021-32765 | — | MISS | — |
| VUL-CVE-2021-33586 | — | MISS | — |
| VUL-CVE-2021-33796 | — | MISS | — |
| VUL-CVE-2021-33797 | — | MISS | — |
| VUL-CVE-2021-33815 | — | MISS | — |
| VUL-CVE-2021-33880 | — | MISS | — |
| VUL-CVE-2021-33910 | — | MISS | — |
| VUL-CVE-2021-35452 | — | MISS | — |
| VUL-CVE-2021-3570 | — | MISS | — |
| VUL-CVE-2021-36082 | — | MISS | — |
| VUL-CVE-2021-36084 | — | MISS | — |
| VUL-CVE-2021-36085 | — | MISS | — |
| VUL-CVE-2021-36086 | — | MISS | — |
| VUL-CVE-2021-36087 | — | MISS | — |
| VUL-CVE-2021-36409 | — | MISS | — |
| VUL-CVE-2021-36411 | — | MISS | — |
| VUL-CVE-2021-3658 | — | MISS | — |
| VUL-CVE-2021-3660 | — | MISS | — |
| VUL-CVE-2021-36647 | — | MISS | — |
| VUL-CVE-2021-36692 | — | MISS | — |
| VUL-CVE-2021-37232 | — | MISS | — |
| VUL-CVE-2021-37594 | — | MISS | — |
| VUL-CVE-2021-37595 | — | MISS | — |
| VUL-CVE-2021-37635 | — | MISS | — |
| VUL-CVE-2021-37636 | — | MISS | — |
| VUL-CVE-2021-37637 | — | MISS | — |
| VUL-CVE-2021-37638 | — | MISS | — |
| VUL-CVE-2021-37639 | — | MISS | — |
| VUL-CVE-2021-37640 | — | MISS | — |
| VUL-CVE-2021-37641 | — | MISS | — |
| VUL-CVE-2021-37642 | — | MISS | — |
| VUL-CVE-2021-37643 | — | MISS | — |
| VUL-CVE-2021-37644 | — | MISS | — |
| VUL-CVE-2021-37645 | — | MISS | — |
| VUL-CVE-2021-37646 | — | MISS | — |
| VUL-CVE-2021-37647 | — | MISS | — |
| VUL-CVE-2021-37648 | — | MISS | — |
| VUL-CVE-2021-37649 | — | MISS | — |
| VUL-CVE-2021-37650 | — | MISS | — |
| VUL-CVE-2021-37651 | — | MISS | — |
| VUL-CVE-2021-37652 | — | MISS | — |
| VUL-CVE-2021-37653 | — | MISS | — |
| VUL-CVE-2021-37654 | — | MISS | — |
| VUL-CVE-2021-37655 | — | MISS | — |
| VUL-CVE-2021-37656 | — | MISS | — |
| VUL-CVE-2021-37657 | — | MISS | — |
| VUL-CVE-2021-37658 | — | MISS | — |
| VUL-CVE-2021-37659 | — | MISS | — |
| VUL-CVE-2021-37660 | — | MISS | — |
| VUL-CVE-2021-37661 | — | MISS | — |
| VUL-CVE-2021-37662 | — | MISS | — |
| VUL-CVE-2021-37663 | — | MISS | — |
| VUL-CVE-2021-37664 | — | MISS | — |
| VUL-CVE-2021-37665 | — | MISS | — |
| VUL-CVE-2021-37666 | — | MISS | — |
| VUL-CVE-2021-37667 | — | MISS | — |
| VUL-CVE-2021-37668 | — | MISS | — |
| VUL-CVE-2021-37669 | — | MISS | — |
| VUL-CVE-2021-37670 | — | MISS | — |
| VUL-CVE-2021-37671 | — | MISS | — |
| VUL-CVE-2021-37672 | — | MISS | — |
| VUL-CVE-2021-37673 | — | MISS | — |
| VUL-CVE-2021-37674 | — | MISS | — |
| VUL-CVE-2021-37675 | — | MISS | — |
| VUL-CVE-2021-37676 | — | MISS | — |
| VUL-CVE-2021-37677 | — | MISS | — |
| VUL-CVE-2021-37678 | — | MISS | — |
| VUL-CVE-2021-37679 | — | MISS | — |
| VUL-CVE-2021-37680 | — | MISS | — |
| VUL-CVE-2021-37681 | — | MISS | — |
| VUL-CVE-2021-37682 | — | MISS | — |
| VUL-CVE-2021-37683 | — | MISS | — |
| VUL-CVE-2021-37684 | — | MISS | — |
| VUL-CVE-2021-37685 | — | MISS | — |
| VUL-CVE-2021-37686 | — | MISS | — |
| VUL-CVE-2021-37687 | — | MISS | — |
| VUL-CVE-2021-37688 | — | MISS | — |
| VUL-CVE-2021-37689 | — | MISS | — |
| VUL-CVE-2021-37690 | — | MISS | — |
| VUL-CVE-2021-37691 | — | MISS | — |
| VUL-CVE-2021-37692 | — | MISS | — |
| VUL-CVE-2021-38090 | — | MISS | — |
| VUL-CVE-2021-38091 | — | MISS | — |
| VUL-CVE-2021-38092 | — | MISS | — |
| VUL-CVE-2021-38093 | — | MISS | — |
| VUL-CVE-2021-38094 | — | MISS | — |
| VUL-CVE-2021-38114 | — | MISS | — |
| VUL-CVE-2021-38171 | — | MISS | — |
| VUL-CVE-2021-38291 | — | MISS | — |
| VUL-CVE-2021-3997 | — | MISS | — |
| VUL-CVE-2021-40153 | — | MISS | — |
| VUL-CVE-2021-4048 | — | MISS | — |
| VUL-CVE-2021-40540 | — | MISS | — |
| VUL-CVE-2021-4076 | — | MISS | — |
| VUL-CVE-2021-41039 | — | MISS | — |
| VUL-CVE-2021-41072 | — | MISS | — |
| VUL-CVE-2021-41103 | — | MISS | — |
| VUL-CVE-2021-41195 | — | MISS | — |
| VUL-CVE-2021-41196 | — | MISS | — |
| VUL-CVE-2021-41197 | — | MISS | — |
| VUL-CVE-2021-41198 | — | MISS | — |
| VUL-CVE-2021-41199 | — | MISS | — |
| VUL-CVE-2021-41200 | — | MISS | — |
| VUL-CVE-2021-41201 | — | MISS | — |
| VUL-CVE-2021-41202 | — | MISS | — |
| VUL-CVE-2021-41203 | — | MISS | — |
| VUL-CVE-2021-41204 | — | MISS | — |
| VUL-CVE-2021-41205 | — | MISS | — |
| VUL-CVE-2021-41206 | — | MISS | — |
| VUL-CVE-2021-41207 | — | MISS | — |
| VUL-CVE-2021-41208 | — | MISS | — |
| VUL-CVE-2021-41209 | — | MISS | — |
| VUL-CVE-2021-41210 | — | MISS | — |
| VUL-CVE-2021-41211 | — | MISS | — |
| VUL-CVE-2021-41212 | — | MISS | — |
| VUL-CVE-2021-41213 | — | MISS | — |
| VUL-CVE-2021-41214 | — | MISS | — |
| VUL-CVE-2021-41215 | — | MISS | — |
| VUL-CVE-2021-41216 | — | MISS | — |
| VUL-CVE-2021-41217 | — | MISS | — |
| VUL-CVE-2021-41218 | — | MISS | — |
| VUL-CVE-2021-41219 | — | MISS | — |
| VUL-CVE-2021-41220 | — | MISS | — |
| VUL-CVE-2021-41221 | — | MISS | — |
| VUL-CVE-2021-41222 | — | MISS | — |
| VUL-CVE-2021-41223 | — | MISS | — |
| VUL-CVE-2021-41224 | — | MISS | — |
| VUL-CVE-2021-41225 | — | MISS | — |
| VUL-CVE-2021-41226 | — | MISS | — |
| VUL-CVE-2021-41227 | — | MISS | — |
| VUL-CVE-2021-41228 | — | MISS | — |
| VUL-CVE-2021-41253 | — | MISS | — |
| VUL-CVE-2021-42778 | — | MISS | — |
| VUL-CVE-2021-42779 | — | MISS | — |
| VUL-CVE-2021-42780 | — | MISS | — |
| VUL-CVE-2021-42781 | — | MISS | — |
| VUL-CVE-2021-42782 | — | MISS | — |
| VUL-CVE-2021-43400 | — | MISS | — |
| VUL-CVE-2021-43521 | — | MISS | — |
| VUL-CVE-2021-43666 | — | MISS | — |
| VUL-CVE-2021-43784 | — | MISS | — |
| VUL-CVE-2021-43816 | — | MISS | — |
| VUL-CVE-2021-44108 | — | MISS | — |
| VUL-CVE-2021-44109 | — | MISS | — |
| VUL-CVE-2021-44225 | — | MISS | — |
| VUL-CVE-2021-44513 | — | MISS | — |
| VUL-CVE-2021-44647 | — | MISS | — |
| VUL-CVE-2021-44732 | — | MISS | — |
| VUL-CVE-2021-45005 | — | MISS | — |
| VUL-CVE-2021-45386 | — | MISS | — |
| VUL-CVE-2021-45462 | — | MISS | — |
| VUL-CVE-2021-45931 | — | MISS | — |
| VUL-CVE-2021-45985 | — | MISS | — |
| VUL-CVE-2021-46822 | — | MISS | — |
| VUL-CVE-2022-0204 | — | MISS | — |
| VUL-CVE-2022-0367 | — | MISS | — |
| VUL-CVE-2022-1475 | — | MISS | — |
| VUL-CVE-2022-21159 | — | MISS | — |
| VUL-CVE-2022-21725 | — | MISS | — |
| VUL-CVE-2022-21726 | — | MISS | — |
| VUL-CVE-2022-21727 | — | MISS | — |
| VUL-CVE-2022-21728 | — | MISS | — |
| VUL-CVE-2022-21729 | — | MISS | — |
| VUL-CVE-2022-21730 | — | MISS | — |
| VUL-CVE-2022-21731 | — | MISS | — |
| VUL-CVE-2022-21732 | — | MISS | — |
| VUL-CVE-2022-21733 | — | MISS | — |
| VUL-CVE-2022-21734 | — | MISS | — |
| VUL-CVE-2022-21735 | — | MISS | — |
| VUL-CVE-2022-21736 | — | MISS | — |
| VUL-CVE-2022-21737 | — | MISS | — |
| VUL-CVE-2022-21738 | — | MISS | — |
| VUL-CVE-2022-21739 | — | MISS | — |
| VUL-CVE-2022-21740 | — | MISS | — |
| VUL-CVE-2022-21741 | — | MISS | — |
| VUL-CVE-2022-22576 | — | MISS | — |
| VUL-CVE-2022-23471 | — | MISS | — |
| VUL-CVE-2022-23557 | — | MISS | — |
| VUL-CVE-2022-23558 | — | MISS | — |
| VUL-CVE-2022-23559 | — | MISS | — |
| VUL-CVE-2022-23560 | — | MISS | — |
| VUL-CVE-2022-23561 | — | MISS | — |
| VUL-CVE-2022-23562 | — | MISS | — |
| VUL-CVE-2022-23564 | — | MISS | — |
| VUL-CVE-2022-23565 | — | MISS | — |
| VUL-CVE-2022-23566 | — | MISS | — |
| VUL-CVE-2022-23567 | — | MISS | — |
| VUL-CVE-2022-23568 | — | MISS | — |
| VUL-CVE-2022-23570 | — | MISS | — |
| VUL-CVE-2022-23571 | — | MISS | — |
| VUL-CVE-2022-23572 | — | MISS | — |
| VUL-CVE-2022-23573 | — | MISS | — |
| VUL-CVE-2022-23574 | — | MISS | — |
| VUL-CVE-2022-23575 | — | MISS | — |
| VUL-CVE-2022-23576 | — | MISS | — |
| VUL-CVE-2022-23577 | — | MISS | — |
| VUL-CVE-2022-23578 | — | MISS | — |
| VUL-CVE-2022-23579 | — | MISS | — |
| VUL-CVE-2022-23580 | — | MISS | — |
| VUL-CVE-2022-23581 | — | MISS | — |
| VUL-CVE-2022-23582 | — | MISS | — |
| VUL-CVE-2022-23583 | — | MISS | — |
| VUL-CVE-2022-23584 | — | MISS | — |
| VUL-CVE-2022-23585 | — | MISS | — |
| VUL-CVE-2022-23586 | — | MISS | — |
| VUL-CVE-2022-23587 | — | MISS | — |
| VUL-CVE-2022-23588 | — | MISS | — |
| VUL-CVE-2022-23589 | — | MISS | — |
| VUL-CVE-2022-23590 | — | MISS | — |
| VUL-CVE-2022-23591 | — | MISS | — |
| VUL-CVE-2022-23592 | — | MISS | — |
| VUL-CVE-2022-23593 | — | MISS | — |
| VUL-CVE-2022-23595 | — | MISS | — |
| VUL-CVE-2022-23613 | — | MISS | — |
| VUL-CVE-2022-23648 | — | MISS | — |
| VUL-CVE-2022-24795 | — | MISS | — |
| VUL-CVE-2022-24883 | — | MISS | — |
| VUL-CVE-2022-24884 | — | MISS | — |
| VUL-CVE-2022-25051 | — | MISS | — |
| VUL-CVE-2022-2526 | — | MISS | — |
| VUL-CVE-2022-25309 | — | MISS | — |
| VUL-CVE-2022-2566 | — | MISS | — |
| VUL-CVE-2022-25761 | — | MISS | — |
| VUL-CVE-2022-2652 | — | MISS | — |
| VUL-CVE-2022-27404 | — | MISS | — |
| VUL-CVE-2022-27406 | — | MISS | — |
| VUL-CVE-2022-27418 | — | MISS | — |
| VUL-CVE-2022-27419 | — | MISS | — |
| VUL-CVE-2022-27649 | — | MISS | — |
| VUL-CVE-2022-27650 | — | MISS | — |
| VUL-CVE-2022-27775 | — | MISS | — |
| VUL-CVE-2022-27776 | — | MISS | — |
| VUL-CVE-2022-27779 | — | MISS | — |
| VUL-CVE-2022-27781 | — | MISS | — |
| VUL-CVE-2022-27782 | — | MISS | — |
| VUL-CVE-2022-27939 | — | MISS | — |
| VUL-CVE-2022-27940 | — | MISS | — |
| VUL-CVE-2022-27941 | — | MISS | — |
| VUL-CVE-2022-27942 | — | MISS | — |
| VUL-CVE-2022-28550 | — | MISS | — |
| VUL-CVE-2022-28805 | — | MISS | — |
| VUL-CVE-2022-29162 | — | MISS | — |
| VUL-CVE-2022-29191 | — | MISS | — |
| VUL-CVE-2022-29192 | — | MISS | — |
| VUL-CVE-2022-29193 | — | MISS | — |
| VUL-CVE-2022-29194 | — | MISS | — |
| VUL-CVE-2022-29195 | — | MISS | — |
| VUL-CVE-2022-29196 | — | MISS | — |
| VUL-CVE-2022-29197 | — | MISS | — |
| VUL-CVE-2022-29198 | — | MISS | — |
| VUL-CVE-2022-29199 | — | MISS | — |
| VUL-CVE-2022-29200 | — | MISS | — |
| VUL-CVE-2022-29201 | — | MISS | — |
| VUL-CVE-2022-29202 | — | MISS | — |
| VUL-CVE-2022-29203 | — | MISS | — |
| VUL-CVE-2022-29204 | — | MISS | — |
| VUL-CVE-2022-29205 | — | MISS | — |
| VUL-CVE-2022-29206 | — | MISS | — |
| VUL-CVE-2022-29207 | — | MISS | — |
| VUL-CVE-2022-29208 | — | MISS | — |
| VUL-CVE-2022-29209 | — | MISS | — |
| VUL-CVE-2022-29210 | — | MISS | — |
| VUL-CVE-2022-29211 | — | MISS | — |
| VUL-CVE-2022-29212 | — | MISS | — |
| VUL-CVE-2022-29213 | — | MISS | — |
| VUL-CVE-2022-29216 | — | MISS | — |
| VUL-CVE-2022-29264 | — | MISS | — |
| VUL-CVE-2022-2970 | — | MISS | — |
| VUL-CVE-2022-3008 | — | MISS | — |
| VUL-CVE-2022-30767 | — | MISS | — |
| VUL-CVE-2022-31030 | — | MISS | — |
| VUL-CVE-2022-3109 | — | MISS | — |
| VUL-CVE-2022-32205 | — | MISS | — |
| VUL-CVE-2022-32207 | — | MISS | — |
| VUL-CVE-2022-32208 | — | MISS | — |
| VUL-CVE-2022-32221 | — | MISS | — |
| VUL-CVE-2022-3299 | — | MISS | — |
| VUL-CVE-2022-33068 | — | MISS | — |
| VUL-CVE-2022-33070 | — | MISS | — |
| VUL-CVE-2022-33099 | — | MISS | — |
| VUL-CVE-2022-3341 | — | MISS | — |
| VUL-CVE-2022-34835 | — | MISS | — |
| VUL-CVE-2022-35252 | — | MISS | — |
| VUL-CVE-2022-35409 | — | MISS | — |
| VUL-CVE-2022-35934 | — | MISS | — |
| VUL-CVE-2022-35935 | — | MISS | — |
| VUL-CVE-2022-35937 | — | MISS | — |
| VUL-CVE-2022-35939 | — | MISS | — |
| VUL-CVE-2022-35940 | — | MISS | — |
| VUL-CVE-2022-35941 | — | MISS | — |
| VUL-CVE-2022-35952 | — | MISS | — |
| VUL-CVE-2022-35959 | — | MISS | — |
| VUL-CVE-2022-35960 | — | MISS | — |
| VUL-CVE-2022-35963 | — | MISS | — |
| VUL-CVE-2022-35964 | — | MISS | — |
| VUL-CVE-2022-35965 | — | MISS | — |
| VUL-CVE-2022-35966 | — | MISS | — |
| VUL-CVE-2022-35967 | — | MISS | — |
| VUL-CVE-2022-35968 | — | MISS | — |
| VUL-CVE-2022-35969 | — | MISS | — |
| VUL-CVE-2022-35970 | — | MISS | — |
| VUL-CVE-2022-35971 | — | MISS | — |
| VUL-CVE-2022-35972 | — | MISS | — |
| VUL-CVE-2022-35973 | — | MISS | — |
| VUL-CVE-2022-35974 | — | MISS | — |
| VUL-CVE-2022-35979 | — | MISS | — |
| VUL-CVE-2022-35981 | — | MISS | — |
| VUL-CVE-2022-35982 | — | MISS | — |
| VUL-CVE-2022-35983 | — | MISS | — |
| VUL-CVE-2022-35984 | — | MISS | — |
| VUL-CVE-2022-35985 | — | MISS | — |
| VUL-CVE-2022-35986 | — | MISS | — |
| VUL-CVE-2022-35987 | — | MISS | — |
| VUL-CVE-2022-35988 | — | MISS | — |
| VUL-CVE-2022-35989 | — | MISS | — |
| VUL-CVE-2022-35990 | — | MISS | — |
| VUL-CVE-2022-35991 | — | MISS | — |
| VUL-CVE-2022-35992 | — | MISS | — |
| VUL-CVE-2022-35993 | — | MISS | — |
| VUL-CVE-2022-35994 | — | MISS | — |
| VUL-CVE-2022-35995 | — | MISS | — |
| VUL-CVE-2022-35996 | — | MISS | — |
| VUL-CVE-2022-35997 | — | MISS | — |
| VUL-CVE-2022-35998 | — | MISS | — |
| VUL-CVE-2022-35999 | — | MISS | — |
| VUL-CVE-2022-36000 | — | MISS | — |
| VUL-CVE-2022-36001 | — | MISS | — |
| VUL-CVE-2022-36002 | — | MISS | — |
| VUL-CVE-2022-36003 | — | MISS | — |
| VUL-CVE-2022-36004 | — | MISS | — |
| VUL-CVE-2022-36005 | — | MISS | — |
| VUL-CVE-2022-36011 | — | MISS | — |
| VUL-CVE-2022-36012 | — | MISS | — |
| VUL-CVE-2022-36013 | — | MISS | — |
| VUL-CVE-2022-36014 | — | MISS | — |
| VUL-CVE-2022-36015 | — | MISS | — |
| VUL-CVE-2022-36016 | — | MISS | — |
| VUL-CVE-2022-36017 | — | MISS | — |
| VUL-CVE-2022-36018 | — | MISS | — |
| VUL-CVE-2022-36019 | — | MISS | — |
| VUL-CVE-2022-36026 | — | MISS | — |
| VUL-CVE-2022-36027 | — | MISS | — |
| VUL-CVE-2022-37047 | — | MISS | — |
| VUL-CVE-2022-37048 | — | MISS | — |
| VUL-CVE-2022-37049 | — | MISS | — |
| VUL-CVE-2022-37434 | — | MISS | — |
| VUL-CVE-2022-37451 | — | MISS | — |
| VUL-CVE-2022-37452 | — | MISS | — |
| VUL-CVE-2022-3821 | — | MISS | — |
| VUL-CVE-2022-39177 | — | MISS | — |
| VUL-CVE-2022-39274 | — | MISS | — |
| VUL-CVE-2022-39316 | — | MISS | — |
| VUL-CVE-2022-39318 | — | MISS | — |
| VUL-CVE-2022-39319 | — | MISS | — |
| VUL-CVE-2022-39347 | — | MISS | — |
| VUL-CVE-2022-3964 | — | MISS | — |
| VUL-CVE-2022-3965 | — | MISS | — |
| VUL-CVE-2022-3976 | — | MISS | — |
| VUL-CVE-2022-40897 | — | MISS | — |
| VUL-CVE-2022-4121 | — | MISS | — |
| VUL-CVE-2022-41877 | — | MISS | — |
| VUL-CVE-2022-41880 | — | MISS | — |
| VUL-CVE-2022-41883 | — | MISS | — |
| VUL-CVE-2022-41884 | — | MISS | — |
| VUL-CVE-2022-41885 | — | MISS | — |
| VUL-CVE-2022-41886 | — | MISS | — |
| VUL-CVE-2022-41887 | — | MISS | — |
| VUL-CVE-2022-41888 | — | MISS | — |
| VUL-CVE-2022-41889 | — | MISS | — |
| VUL-CVE-2022-41890 | — | MISS | — |
| VUL-CVE-2022-41891 | — | MISS | — |
| VUL-CVE-2022-41893 | — | MISS | — |
| VUL-CVE-2022-41894 | — | MISS | — |
| VUL-CVE-2022-41895 | — | MISS | — |
| VUL-CVE-2022-41896 | — | MISS | — |
| VUL-CVE-2022-41897 | — | MISS | — |
| VUL-CVE-2022-41898 | — | MISS | — |
| VUL-CVE-2022-41899 | — | MISS | — |
| VUL-CVE-2022-41900 | — | MISS | — |
| VUL-CVE-2022-41901 | — | MISS | — |
| VUL-CVE-2022-41902 | — | MISS | — |
| VUL-CVE-2022-41907 | — | MISS | — |
| VUL-CVE-2022-41908 | — | MISS | — |
| VUL-CVE-2022-41909 | — | MISS | — |
| VUL-CVE-2022-41910 | — | MISS | — |
| VUL-CVE-2022-41911 | — | MISS | — |
| VUL-CVE-2022-4415 | — | MISS | — |
| VUL-CVE-2022-44789 | — | MISS | — |
| VUL-CVE-2022-45873 | — | MISS | — |
| VUL-CVE-2022-46165 | — | MISS | — |
| VUL-CVE-2022-46393 | — | MISS | — |
| VUL-CVE-2022-47021 | — | MISS | — |
| VUL-CVE-2022-47665 | — | MISS | — |
| VUL-CVE-2022-48340 | — | MISS | — |
| VUL-CVE-2022-48434 | — | MISS | — |
| VUL-CVE-2022-48468 | — | MISS | — |
| VUL-CVE-2022-4904 | — | MISS | — |
| VUL-CVE-2023-0645 | — | MISS | — |
| VUL-CVE-2023-1428 | — | MISS | — |
| VUL-CVE-2023-1672 | — | MISS | — |
| VUL-CVE-2023-1801 | — | MISS | — |
| VUL-CVE-2023-23916 | — | MISS | — |
| VUL-CVE-2023-24751 | — | MISS | — |
| VUL-CVE-2023-24805 | — | MISS | — |
| VUL-CVE-2023-24817 | — | MISS | — |
| VUL-CVE-2023-24825 | — | MISS | — |
| VUL-CVE-2023-24826 | — | MISS | — |
| VUL-CVE-2023-25153 | — | MISS | — |
| VUL-CVE-2023-25173 | — | MISS | — |
| VUL-CVE-2023-25193 | — | MISS | — |
| VUL-CVE-2023-25221 | — | MISS | — |
| VUL-CVE-2023-25658 | — | MISS | — |
| VUL-CVE-2023-25659 | — | MISS | — |
| VUL-CVE-2023-25660 | — | MISS | — |
| VUL-CVE-2023-25661 | — | MISS | — |
| VUL-CVE-2023-25662 | — | MISS | — |
| VUL-CVE-2023-25663 | — | MISS | — |
| VUL-CVE-2023-25664 | — | MISS | — |
| VUL-CVE-2023-25665 | — | MISS | — |
| VUL-CVE-2023-25666 | — | MISS | — |
| VUL-CVE-2023-25667 | — | MISS | — |
| VUL-CVE-2023-25668 | — | MISS | — |
| VUL-CVE-2023-25669 | — | MISS | — |
| VUL-CVE-2023-25670 | — | MISS | — |
| VUL-CVE-2023-25671 | — | MISS | — |
| VUL-CVE-2023-25672 | — | MISS | — |
| VUL-CVE-2023-25673 | — | MISS | — |
| VUL-CVE-2023-25674 | — | MISS | — |
| VUL-CVE-2023-25675 | — | MISS | — |
| VUL-CVE-2023-25676 | — | MISS | — |
| VUL-CVE-2023-25801 | — | MISS | — |
| VUL-CVE-2023-25809 | — | MISS | — |
| VUL-CVE-2023-26123 | — | MISS | — |
| VUL-CVE-2023-27102 | — | MISS | — |
| VUL-CVE-2023-27103 | — | MISS | — |
| VUL-CVE-2023-27533 | — | MISS | — |
| VUL-CVE-2023-27534 | — | MISS | — |
| VUL-CVE-2023-27535 | — | MISS | — |
| VUL-CVE-2023-27538 | — | MISS | — |
| VUL-CVE-2023-27579 | — | MISS | — |
| VUL-CVE-2023-27772 | — | MISS | — |
| VUL-CVE-2023-27783 | — | MISS | — |
| VUL-CVE-2023-2804 | — | MISS | — |
| VUL-CVE-2023-28320 | — | MISS | — |
| VUL-CVE-2023-28321 | — | MISS | — |
| VUL-CVE-2023-28322 | — | MISS | — |
| VUL-CVE-2023-28366 | — | MISS | — |
| VUL-CVE-2023-28371 | — | MISS | — |
| VUL-CVE-2023-29383 | — | MISS | — |
| VUL-CVE-2023-29416 | — | MISS | — |
| VUL-CVE-2023-29418 | — | MISS | — |
| VUL-CVE-2023-29419 | — | MISS | — |
| VUL-CVE-2023-29420 | — | MISS | — |
| VUL-CVE-2023-31124 | — | MISS | — |
| VUL-CVE-2023-31130 | — | MISS | — |
| VUL-CVE-2023-31147 | — | MISS | — |
| VUL-CVE-2023-31922 | — | MISS | — |
| VUL-CVE-2023-31982 | — | MISS | — |
| VUL-CVE-2023-32067 | — | MISS | — |
| VUL-CVE-2023-33973 | — | MISS | — |
| VUL-CVE-2023-33974 | — | MISS | — |
| VUL-CVE-2023-33975 | — | MISS | — |
| VUL-CVE-2023-36326 | — | MISS | — |
| VUL-CVE-2023-36327 | — | MISS | — |
| VUL-CVE-2023-36811 | — | MISS | — |
| VUL-CVE-2023-37185 | — | MISS | — |
| VUL-CVE-2023-37186 | — | MISS | — |
| VUL-CVE-2023-37187 | — | MISS | — |
| VUL-CVE-2023-37188 | — | MISS | — |
| VUL-CVE-2023-37276 | — | MISS | — |
| VUL-CVE-2023-37457 | — | MISS | — |
| VUL-CVE-2023-38546 | — | MISS | — |
| VUL-CVE-2023-39150 | — | MISS | — |
| VUL-CVE-2023-39350 | — | MISS | — |
| VUL-CVE-2023-39354 | — | MISS | — |
| VUL-CVE-2023-39355 | — | MISS | — |
| VUL-CVE-2023-39976 | — | MISS | — |
| VUL-CVE-2023-40032 | — | MISS | — |
| VUL-CVE-2023-40184 | — | MISS | — |
| VUL-CVE-2023-40589 | — | MISS | — |
| VUL-CVE-2023-41419 | — | MISS | — |
| VUL-CVE-2023-42822 | — | MISS | — |
| VUL-CVE-2023-43887 | — | MISS | — |
| VUL-CVE-2023-45199 | — | MISS | — |
| VUL-CVE-2023-4535 | — | MISS | — |
| VUL-CVE-2023-45853 | — | MISS | — |
| VUL-CVE-2023-46218 | — | MISS | — |
| VUL-CVE-2023-46407 | — | MISS | — |
| VUL-CVE-2023-47470 | — | MISS | — |
| VUL-CVE-2023-47471 | — | MISS | — |
| VUL-CVE-2023-47627 | — | MISS | — |
| VUL-CVE-2023-48106 | — | MISS | — |
| VUL-CVE-2023-48183 | — | MISS | — |
| VUL-CVE-2023-48184 | — | MISS | — |
| VUL-CVE-2023-4863 | — | MISS | — |
| VUL-CVE-2023-49294 | — | MISS | — |
| VUL-CVE-2023-49467 | — | MISS | — |
| VUL-CVE-2023-49786 | — | MISS | — |
| VUL-CVE-2023-50019 | — | MISS | — |
| VUL-CVE-2023-50020 | — | MISS | — |
| VUL-CVE-2023-50471 | — | MISS | — |
| VUL-CVE-2023-50472 | — | MISS | — |
| VUL-CVE-2023-52353 | — | MISS | — |
| VUL-CVE-2023-5632 | — | MISS | — |
| VUL-CVE-2023-7152 | — | MISS | — |
| VUL-CVE-2024-21626 | — | MISS | — |
| VUL-CVE-2024-22211 | — | MISS | — |
| VUL-CVE-2024-22365 | — | MISS | — |
| VUL-CVE-2024-22860 | — | MISS | — |
| VUL-CVE-2024-22861 | — | MISS | — |
| VUL-CVE-2024-22862 | — | MISS | — |
| VUL-CVE-2024-23170 | — | MISS | — |
| VUL-CVE-2024-23775 | — | MISS | — |
| VUL-CVE-2024-23829 | — | MISS | — |
| VUL-CVE-2024-24806 | — | MISS | — |
| VUL-CVE-2024-28755 | — | MISS | — |
| VUL-CVE-2024-28836 | — | MISS | — |
| VUL-CVE-2024-28960 | — | MISS | — |
| XFL-001 | `core/gold-standard-testbed/covert_channel_dns.java` | HIT | Semgrep + marker |
| XFL-002 | `core/gold-standard-testbed/covert_channel_dns.java` | HIT | Marker (testbed) |
| XFL-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| XFL-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| XFL-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| XFL-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| XFL-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| XFL-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| XFL-009 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| XFL-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| XML-001 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| XML-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| XML-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| XML-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| XML-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| XML-006 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| XML-007 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| XML-008 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| XML-009 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| XML-010 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |

## Summary

| Metric | Value |
|---|---|
| Rules expected | 9489 |
| HIT | 4099 |
| MISS | 5390 |
| Semgrep + marker | 626 |
| Semgrep only | 99 |
| Marker only (Semgrep parse/skip) | 3374 |

## Compliance status (Paladin — OWASP / MITRE / NIST)

Per-rule tags are inferred from CWE tokens in `core/skills/*/patterns.md` (see `scripts/compliance_layer.py`). **NIST SSDF** practice counts below are heuristic overlays on the OWASP distribution (themes of coverage), not a formal NIST assessment.

### OWASP Top 10 (2021) — rule coverage

| Category | Rules (tag count) |
|---|---|
| A01 | 509 |
| A02 | 112 |
| A03 | 425 |
| A04 | 7269 |
| A05 | 415 |
| A06 | 34 |
| A07 | 185 |
| A08 | 339 |
| A09 | 59 |
| A10 | 203 |

### MITRE ATT&CK Enterprise — technique frequency (top 25)

| Technique | Rules |
|---|---|
| `T1190` | 7903 |
| `T1098` | 458 |
| `T1059` | 288 |
| `T1059.004` | 239 |
| `T1204` | 232 |
| `T1055` | 215 |
| `T1059.007` | 195 |
| `T1005` | 142 |
| `T1078` | 134 |
| `T1552` | 125 |
| `T1195` | 117 |
| `T1189` | 81 |
| `T1195.001` | 76 |
| `T1083` | 51 |
| `T1562` | 46 |
| `T1556` | 40 |
| `T1550` | 18 |
| `T1110` | 16 |
| `T1499` | 13 |
| `T1548` | 3 |

### NIST SSDF (SP 800-218) — heuristic practice signal

| Practice | Description | Rules (heuristic) |
|---|---|---|
| PO.1 | Prepare the organization — development security requirements are defined and tracked | 9548 |
| PO.3 | Produce well-secured software — minimize vulnerabilities in releases | 788 |
| PS.1 | Protect all forms of code — supply chain and integrity controls | 7381 |
| PS.2 | Provide verified security requirements — threat modeling & secure design | 934 |
| PS.3 | Architect & produce secure software — configuration and hardening | 474 |
| RB.1 | Review & assess security posture — assurance and monitoring | 262 |
| RV.1 | Identify & respond to vulnerabilities — find, triage, remediate | 93 |
