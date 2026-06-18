# Vulnerable: FAS-243
requests.patch("https://example.org", body=json.dumps({"hello": True}), timeout=5)
