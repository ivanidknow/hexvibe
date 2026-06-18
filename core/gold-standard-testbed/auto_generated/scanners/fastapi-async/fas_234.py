# Vulnerable: FAS-234
cipher = pycryptodomex_arc4.new(tempkey)
msg = nonce + cipher.encrypt(b'Open the pod bay doors, HAL')
