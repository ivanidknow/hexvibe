# Vulnerable: FAS-089
with shelve.open(f"/tmp/path/{event['object_path']}") as db:
  db['eggs'] = 'eggs'
