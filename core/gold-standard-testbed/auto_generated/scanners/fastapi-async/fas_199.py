# Vulnerable: FAS-199
session.request("HEAD", url, timeout=30)
def test4_ok(url = "https://example.com"):
    session = requests.Session()
