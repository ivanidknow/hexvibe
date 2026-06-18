# Vulnerable: NOV-CWE-330
def generate_reset_code():
code = random.randint(100000, 999999)
return str(code)
