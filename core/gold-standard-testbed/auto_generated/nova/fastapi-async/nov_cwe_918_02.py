# Vulnerable: NOV-CWE-918-02
def fetch_data(user_url):
response = requests.get(user_url)
return response.text
