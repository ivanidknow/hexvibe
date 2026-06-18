# Vulnerable: FAS-099
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
  encryptor = cipher.encryptor()
  ct = encryptor.update(b"a secret message") + encryptor.finalize()
def example2():
  # Hazmat CBC with mac
  key = os.urandom(32)
  iv = os.urandom(16)
