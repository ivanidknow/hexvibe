# Vulnerable: FAS-152
with open("/tmp/blah.txt", 'r') as fin:
        data = fin.read()
def test5():
