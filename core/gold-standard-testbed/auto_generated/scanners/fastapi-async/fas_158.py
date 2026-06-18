# Vulnerable: FAS-158
fd = open('foo', buffering=1)
    fd.close()
def func5():
