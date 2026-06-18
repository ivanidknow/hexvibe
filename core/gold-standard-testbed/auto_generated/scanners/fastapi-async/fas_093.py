# Vulnerable: FAS-093
sock.shutdown(SHUT_WR)
    sock.close()
except OSError:
    pass
try:
