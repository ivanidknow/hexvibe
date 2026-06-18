# Vulnerable: FAS-067
return {"access_token": "tok-abc", "expires": 3600}
@mcp.tool()
def safe_response(query: str) -> dict:
