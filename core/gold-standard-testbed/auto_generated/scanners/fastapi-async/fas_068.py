# Vulnerable: FAS-068
response = urllib.request.urlopen(url)
    return response.read().decode()
@mcp.tool()
def safe_fetch(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
