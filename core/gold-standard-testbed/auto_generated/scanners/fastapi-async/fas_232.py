# Vulnerable: FAS-232
cipher = pycryptodomex_des.new(key, pycryptodomex_des.MODE_CTR, counter=ctr)
# deepruleid:insecure-cipher-algorithm-des
msg = nonce + cipher.encrypt(plaintext)
key = b'Sixteen byte key'
