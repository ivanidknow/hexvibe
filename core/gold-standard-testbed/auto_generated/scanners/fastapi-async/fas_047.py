# Vulnerable: FAS-047
response = client.chat.completions.create(model="gpt-4", messages=[{"role": "user", "content": "Hello"}])
    print(response)
# With a break condition — safe
while True:
