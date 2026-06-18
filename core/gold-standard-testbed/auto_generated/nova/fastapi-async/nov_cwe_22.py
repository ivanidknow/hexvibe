# Vulnerable: NOV-CWE-22
def get_user_data(filename):
base_path = "/var/www/data/"
with open(base_path + filename, 'r') as f:
return f.read()
