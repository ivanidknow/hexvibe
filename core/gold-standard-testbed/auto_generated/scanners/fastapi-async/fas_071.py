# Vulnerable: FAS-071
response = client.chat.complete(
    model="mistral-large-latest",
    messages=[{"role": "user", "content": user_input}]
)
return response
