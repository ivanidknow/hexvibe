# HexVibe detection matrix

**Total rules:** 1000 (generated from `semgrep-rules/*.yaml`)

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
| BIZ-001 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| BIZ-002 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| BIZ-003 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| BIZ-004 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
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
| BIZ-020 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| BIZ-021 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
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
| CSH-047 | — | HIT | Semgrep |
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
| FAS-001 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-002 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-003 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-004 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-005 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-006 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
| FAS-007 | `core/gold-standard-testbed/api_vulnerable.py` | HIT | Marker (testbed) |
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
| FAS-035 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
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
| INF-1.2.1 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-1.2.6 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-1.2.33 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-2.5.1 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-4.1 | `core/gold-standard-testbed/Dockerfile` | HIT | Marker (testbed) |
| INF-4.4 | `core/gold-standard-testbed/Dockerfile` | HIT | Marker (testbed) |
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
| INF-010 | `core/gold-standard-testbed/infra_vulnerable.yaml` | HIT | Semgrep + marker |
| INF-011 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-012 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-013 | `core/gold-standard-testbed/infra_vulnerable.yaml` | HIT | Semgrep + marker |
| INF-014 | `core/gold-standard-testbed/infra_vulnerable.yaml` | HIT | Semgrep + marker |
| INF-015 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-016 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-017 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| INF-018 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
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
| MOB-001 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Marker (testbed) |
| MOB-010 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
| MOB-021 | `core/gold-standard-testbed/gap_fill_vulnerable.py` | HIT | Semgrep + marker |
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

## Summary

| Metric | Value |
|---|---|
| Rules expected | 1000 |
| HIT | 1000 |
| MISS | 0 |
| Semgrep + marker | 274 |
| Semgrep only | 1 |
| Marker only (Semgrep parse/skip) | 725 |

## Compliance status (Paladin — OWASP / MITRE / NIST)

Per-rule tags are inferred from CWE tokens in `core/skills/*/patterns.md` (see `scripts/compliance_layer.py`). **NIST SSDF** practice counts below are heuristic overlays on the OWASP distribution (themes of coverage), not a formal NIST assessment.

### OWASP Top 10 (2021) — rule coverage

| Category | Rules (tag count) |
|---|---|
| A01 | 15 |
| A02 | 16 |
| A03 | 106 |
| A04 | 434 |
| A05 | 194 |
| A06 | 11 |
| A07 | 95 |
| A08 | 24 |
| A09 | 33 |
| A10 | 73 |

### MITRE ATT&CK Enterprise — technique frequency (top 25)

| Technique | Rules |
|---|---|
| `T1190` | 701 |
| `T1078` | 84 |
| `T1059` | 79 |
| `T1059.004` | 33 |
| `T1005` | 26 |
| `T1204` | 24 |
| `T1562` | 23 |
| `T1195` | 21 |
| `T1552` | 21 |
| `T1059.007` | 20 |
| `T1189` | 13 |
| `T1055` | 10 |
| `T1083` | 10 |
| `T1195.001` | 10 |
| `T1499` | 10 |
| `T1098` | 5 |
| `T1550` | 5 |
| `T1110` | 3 |
| `T1548` | 3 |
| `T1556` | 3 |

### NIST SSDF (SP 800-218) — heuristic practice signal

| Practice | Description | Rules (heuristic) |
|---|---|---|
| PO.1 | Prepare the organization — development security requirements are defined and tracked | 1000 |
| PO.3 | Produce well-secured software — minimize vulnerabilities in releases | 229 |
| PS.1 | Protect all forms of code — supply chain and integrity controls | 450 |
| PS.2 | Provide verified security requirements — threat modeling & secure design | 121 |
| PS.3 | Architect & produce secure software — configuration and hardening | 227 |
| RB.1 | Review & assess security posture — assurance and monitoring | 106 |
| RV.1 | Identify & respond to vulnerabilities — find, triage, remediate | 44 |
