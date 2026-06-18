# Vulnerable: FAS-150
jwt.decode(encoded, None, algorithms=['none'])
    return encoded
def ok(secret_key):
