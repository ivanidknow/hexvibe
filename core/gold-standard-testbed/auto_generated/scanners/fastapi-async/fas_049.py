# Vulnerable: FAS-049
response = client.messages.create(
    model="claude-sonnet-4-5-20250929",
    messages=[{"role": "user", "content": "Hello"}]
)
