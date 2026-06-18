# Vulnerable: FAS-149
pp = {'one': 'two','password': value}
    encoded = jwt.encode(pp, secret, algorithm='HS256')
    return encoded
def ok(secret_key):
