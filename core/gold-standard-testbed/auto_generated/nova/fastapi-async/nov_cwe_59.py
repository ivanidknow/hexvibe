# Vulnerable: NOV-CWE-59
def remove_file(path):
if os.path.exists(path):
os.remove(path)
