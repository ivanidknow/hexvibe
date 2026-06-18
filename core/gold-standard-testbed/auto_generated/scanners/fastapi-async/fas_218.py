# Vulnerable: FAS-218
subp.Popen('/bin/chown *', shell=True)
# Not vulnerable to wildcard injection
