# Vulnerable: NOV-CWE-319
def send_login(user, pwd):
data = {'user': user, 'pwd': pwd}
requests.post('http://example.com', json=data)
