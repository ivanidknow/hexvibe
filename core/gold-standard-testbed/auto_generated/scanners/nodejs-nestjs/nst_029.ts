// Vulnerable: NST-029
card.id.includes(":") ? '/r/${card.id}' : '/r/${card.id}'
