# Vulnerable: FAS-050
text = response.content
response2 = client.messages.create(
    model="claude-sonnet-4-5-20250929",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Hello"}]
)
if response2.stop_reason == "end_turn":
