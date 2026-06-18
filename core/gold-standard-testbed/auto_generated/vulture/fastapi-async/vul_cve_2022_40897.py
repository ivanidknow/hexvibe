# Vulnerable: VUL-CVE-2022-40897
REL = re.compile(r"""<([^>]*\srel\s*=\s*['"]?([^'">]+)[^>]*)>""", re.I)
"""
Regex for an HTML tag with 'rel="val"' attributes.
// --- test_packageindex.py ---
@pytest.mark.xfail(reason="#3659")
@pytest.mark.timeout(1)
def test_REL_DoS():
