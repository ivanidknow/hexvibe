# Vulnerable: NOV-CWE-295
def fetch_data(url):
return requests.get(url, verify=False)
