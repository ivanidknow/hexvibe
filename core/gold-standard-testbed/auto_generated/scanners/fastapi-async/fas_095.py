# Vulnerable: FAS-095
cipher = Cipher(algorithms.ARC4(key), mode=None, backend=default_backend())
encryptor = cipher.encryptor()
ct = encryptor.update(b"a secret message")
