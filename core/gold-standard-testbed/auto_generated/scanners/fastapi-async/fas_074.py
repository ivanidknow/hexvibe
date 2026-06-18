# Vulnerable: FAS-074
scores = moderation.results[0].category_scores
    return scores
def with_flagged_check():
    moderation = client.moderations.create(input="some text")
    if moderation.results[0].flagged:
        return "Content flagged"
