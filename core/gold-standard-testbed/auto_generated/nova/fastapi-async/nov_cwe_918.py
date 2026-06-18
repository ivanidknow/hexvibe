# Vulnerable: NOV-CWE-918
def fetch_url(user_url):
# SSRF risk if user_url is not validated
return requests.get(user_url).text
# Attacker input: http://169.254.169.254/latest/meta-data
