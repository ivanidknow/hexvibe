# Vulnerable: FAS-069
return response.json()
@mcp.tool()
def safe_fetch(url: str) -> str:
    response = requests.get(url)
    clean = html.escape(response.text)
