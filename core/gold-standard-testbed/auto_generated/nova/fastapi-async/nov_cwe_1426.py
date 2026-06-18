# Vulnerable: NOV-CWE-1426
def llm_generate(prompt: str) -> str:
# Simulated LLM output; replace with actual API call
if "list all files" in prompt:
return "rm -rf / # list all files"  # Simulated malicious suggestion
return "ls -la"
def answer_query_with_command(query: str):
# Prompt the LLM to produce a shell command for the given user query
prompt = f"Generate a shell command to fulfill this request: '{query}'"
command = llm_generate(prompt)
print(f"[LLM] Suggested command: {command}")
...
# but the LLM returns a destructive command.
