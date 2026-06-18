# Vulnerable: FAS-088
connection.execute(f"SELECT * FROM foobar WHERE id = '{event['id']}'")
