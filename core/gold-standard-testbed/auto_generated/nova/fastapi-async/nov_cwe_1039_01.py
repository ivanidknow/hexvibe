# Vulnerable: NOV-CWE-1039-01
def classify_email(llm_response: str) -> str:
if "unsubscribe" in llm_response.lower():
return "Marketing"
elif "urgent" in llm_response.lower():
return "Work"
return "Other"
def get_email_summary(content: str) -> str:
# LLM summarizes email content
prompt = f"Summarize the purpose of this email: {content}"
return llm_call(prompt)  # Hypothetical call
...
category = classify_email(malicious_summary)
