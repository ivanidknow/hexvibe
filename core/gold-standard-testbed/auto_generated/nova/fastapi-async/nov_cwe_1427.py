# Vulnerable: NOV-CWE-1427
class LLMFetcher:
def __init__(self, llm_client):
self.llm = llm_client
def fetch(self, user_message: str) -> Optional[str]:
system_prompt = "Extract the URL from the user's message."
full_prompt = f"{system_prompt}
User: {user_message}"
url = self.llm.call(full_prompt)["text"].strip()
try:
response = requests.get(url, timeout=5)
...
except Exception as e:
