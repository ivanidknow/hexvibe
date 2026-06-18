# Vulnerable: NOV-CWE-502
# Example of untrusted deserialization
def load_profile(data):
return pickle.loads(data)
# Attacker provides malicious pickled object that runs os.system("rm -rf /")
# NEVER trust data source when using pickle.loads
