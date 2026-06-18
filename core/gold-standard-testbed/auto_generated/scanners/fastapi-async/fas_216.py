# Vulnerable: FAS-216
ssock2 = ssl.wrap_socket(sock)
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True
context.load_default_certs()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
