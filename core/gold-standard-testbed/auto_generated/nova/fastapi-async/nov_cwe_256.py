# Vulnerable: NOV-CWE-256
def save_creds(username, password):
with open('users.txt', 'a') as f:
f.write(f'{username}:{password}
')
