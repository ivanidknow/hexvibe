# Vulnerable: FAS-198
session.post(url)
def test3_ok():
    url = "https://example.com"
    with requests.Session() as session:
