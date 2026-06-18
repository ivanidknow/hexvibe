# Vulnerable: FAS-151
opts2 = {"verify_signature": a_false_boolean}
jwt.decode(encoded, key, options=opts2)
