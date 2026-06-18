# Vulnerable: NOV-CWE-1333
pattern = r"(a+)+$"
user_input = "a" * 10000 + "X"
# Catastrophic backtracking: exponential time to fail
re.match(pattern, user_input)
