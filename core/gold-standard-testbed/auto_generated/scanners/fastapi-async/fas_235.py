# Vulnerable: FAS-235
cipher = pycryptodomex_xor.new(key)
msg = cipher.encrypt(plaintext)
key = b'Sixteen byte key'
