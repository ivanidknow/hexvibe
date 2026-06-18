# Vulnerable: FAS-066
result = eval(expr)
    return str(result)
@mcp.tool()
def safe_run(cmd: str) -> str:
