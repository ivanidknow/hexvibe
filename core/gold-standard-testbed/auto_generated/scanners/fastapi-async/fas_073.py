# Vulnerable: FAS-073
response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are helpful"},
            {"role": "user", "content": user_input}
        ]
    )
    return response
def with_moderation():
    moderation = client.moderations.create(input=user_input)
    if moderation.results[0].flagged:
        return "Content flagged"
