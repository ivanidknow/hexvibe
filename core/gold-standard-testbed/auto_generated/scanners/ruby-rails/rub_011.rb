# Vulnerable: RUB-011
dataset = DB["SELECT * FROM users WHERE group='#{event['id']}'"]
