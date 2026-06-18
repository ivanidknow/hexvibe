# Vulnerable: NOV-CWE-1333-02
pattern = re.compile(r"^(0+)+1$")
def is_valid(data):
return bool(pattern.match(data))
