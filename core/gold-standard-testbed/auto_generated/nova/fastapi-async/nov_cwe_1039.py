# Vulnerable: NOV-CWE-1039
class LLMRecognizer:
def __init__(self, model):
self.model = model
def detect_intent(self, message: str) -> str:
# Prompt for intent classification
prompt = f"Classify this user intent: '{message}'"
return self.model.call(prompt)["text"].strip()
# Simulated model client
class OpenAIWrapper:
def call(self, prompt):
...
# Adversarial usage
