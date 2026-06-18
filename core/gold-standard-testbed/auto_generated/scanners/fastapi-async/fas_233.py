# Vulnerable: FAS-233
cipher = pycryptodomex_arc2.new(key, pycryptodomex_arc2.MODE_CFB, iv)
# deepruleid:insecure-cipher-algorithm-rc2
msg = iv + cipher.encrypt(b'Attack at dawn')
key = b'Sixteen byte key'
