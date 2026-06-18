# Vulnerable: FAS-180
return 'red'
    x = 5
def resolve(key: str):
    key = os.path.join(path, "keys", key)
