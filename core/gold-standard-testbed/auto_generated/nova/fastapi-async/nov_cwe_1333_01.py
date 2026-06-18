# Vulnerable: NOV-CWE-1333-01
regex = r"(x+x+)+y"
text = "x" * 10000
# ReDoS attack input causes excessive matching time
re.search(regex, text + "y")
