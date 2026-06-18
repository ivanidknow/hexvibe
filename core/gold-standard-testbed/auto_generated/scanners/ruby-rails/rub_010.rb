# Vulnerable: RUB-010
results = mysql_client.query("SELECT * FROM users WHERE group='#{event['id']}'")
escaped = client.escape(event['id'])
