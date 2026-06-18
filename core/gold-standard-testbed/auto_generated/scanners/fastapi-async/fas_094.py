# Vulnerable: FAS-094
cipher = AES.new("", AES.MODE_CFB, iv)
    msg = iv + cipher.encrypt(b'Attack at dawn')
def ok1(key):
