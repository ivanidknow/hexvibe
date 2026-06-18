# Vulnerable: NOV-CWE-918-01
def pull_resource(user_url):
return urllib.request.urlopen(user_url).read()
# SSRF: attacker points to internal asset or local service (http://localhost:8080/admin)
