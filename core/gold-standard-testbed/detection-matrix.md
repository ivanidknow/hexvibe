# HexVibe detection matrix

**Total rules:** 4728 (generated from `semgrep-rules/*.yaml`)

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
| CWE-20-HPP | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-20-JS-VAL-EXTRA-01 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-20-JS-VAL-EXTRA-02 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-20-ORM-MASS-ASSIGN | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-20-PY-VAL-EXTRA-01 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-20-PY-VAL-EXTRA-02 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-20-PY-VAL-EXTRA-03 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-20-UNIVERSAL-NULLBYTE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-20-UNIVERSAL-TYPE-CONFUSION | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-22-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-22-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-23-JS-DYNAMIC-REQUIRE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-23-JS-EXPRESS-SENDFILE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-23-PY-TEMPLATE-FILE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-74-JS-LDAP | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-74-PY-LDAP | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-78-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-78-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-79-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-79-JS-SSR-RAW | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-79-JS-VAL-EXTRA-01 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-79-PY-DJANGO-AUTOESCAPE-OFF | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-79-PY-DJANGO-SAFE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-79-PY-HTMLRESPONSE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-79-REACT-DANGEROUSLYSETHTML | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-80-UNIVERSAL-NOSNIFF | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-81-CSH-WEBBROWSER-XSS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-85-174-UNIVERSAL-ONCE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-85-JS-SLASH-FILTER | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
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
| CWE-94-ELECTRON-WEBPREFS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| CWE-94-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-94-NODE-EXEC-CONCAT | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-94-OPENROUTER-PROMPT-CONCAT | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-94-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-94-UNIVERSAL-NO-SANDBOX-TEMPLATE | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-98-UNIVERSAL-FILE-INFRA-CONTROL | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
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
| CWE-174-JS-CANONICAL | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-174-PY-CANONICAL | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-200-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-200-NEXTJS-CLIENT-ENV | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-200-OPENROUTER-APIKEY-LEAK | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-200-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
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
| CWE-749-CSH-COMVISIBLE-DANGEROUS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-749-CSH-SINGLETON-PUBLIC-HOOKS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-755-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-755-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-770-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-770-PY | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-772-JS-BUFFER | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-798-ALEMBIC-URL | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-798-CSH-CONFIG-SECRETS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-862-NEXTJS-SERVER-ACTION | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
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
| CWE-1025-JS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| CWE-1104 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
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
| INF-1.2.1 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-1.2.6 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-1.2.33 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-002 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| INF-2.5.1 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-003 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| INF-004 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Semgrep + marker |
| INF-4.1 | `core/gold-standard-testbed/Dockerfile` | HIT | Marker (testbed) |
| INF-4.4 | `core/gold-standard-testbed/Dockerfile` | HIT | Marker (testbed) |
| INF-005 | `core/gold-standard-testbed/enterprise_java_validation.java` | HIT | Marker (testbed) |
| INF-5.1.1 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-5.1.2-TLS | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-5.2.1 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-5.2.4 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-5.2.5 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-5.3.1 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-5.3.1-NGX | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-5.3.2 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-5.5.1 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-5.6.2 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-5.10 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-5.25 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
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
| Rules expected | 4728 |
| HIT | 4056 |
| MISS | 672 |
| Semgrep + marker | 626 |
| Semgrep only | 56 |
| Marker only (Semgrep parse/skip) | 3374 |

## Compliance status (Paladin — OWASP / MITRE / NIST)

Per-rule tags are inferred from CWE tokens in `core/skills/*/patterns.md` (see `scripts/compliance_layer.py`). **NIST SSDF** practice counts below are heuristic overlays on the OWASP distribution (themes of coverage), not a formal NIST assessment.

### OWASP Top 10 (2021) — rule coverage

| Category | Rules (tag count) |
|---|---|
| A01 | 505 |
| A02 | 110 |
| A03 | 422 |
| A04 | 2471 |
| A05 | 413 |
| A06 | 34 |
| A07 | 184 |
| A08 | 336 |
| A09 | 57 |
| A10 | 197 |

### MITRE ATT&CK Enterprise — technique frequency (top 25)

| Technique | Rules |
|---|---|
| `T1190` | 3099 |
| `T1098` | 457 |
| `T1059` | 286 |
| `T1059.004` | 237 |
| `T1204` | 229 |
| `T1055` | 212 |
| `T1059.007` | 193 |
| `T1005` | 140 |
| `T1078` | 132 |
| `T1552` | 122 |
| `T1195` | 117 |
| `T1195.001` | 76 |
| `T1189` | 65 |
| `T1083` | 48 |
| `T1562` | 44 |
| `T1556` | 40 |
| `T1550` | 18 |
| `T1110` | 15 |
| `T1499` | 13 |
| `T1548` | 3 |

### NIST SSDF (SP 800-218) — heuristic practice signal

| Practice | Description | Rules (heuristic) |
|---|---|---|
| PO.1 | Prepare the organization — development security requirements are defined and tracked | 4728 |
| PO.3 | Produce well-secured software — minimize vulnerabilities in releases | 783 |
| PS.1 | Protect all forms of code — supply chain and integrity controls | 2581 |
| PS.2 | Provide verified security requirements — threat modeling & secure design | 927 |
| PS.3 | Architect & produce secure software — configuration and hardening | 470 |
| RB.1 | Review & assess security posture — assurance and monitoring | 254 |
| RV.1 | Identify & respond to vulnerabilities — find, triage, remediate | 91 |
