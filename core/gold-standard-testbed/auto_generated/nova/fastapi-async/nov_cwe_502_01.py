# Vulnerable: NOV-CWE-502-01
# Load model from file (can be abused if file path is untrusted)
def load_ml_model(model_file):
return joblib.load(open(model_file, "rb"))
# If attacker places a malicious file on disk, loading it can result in code execution
# via Pickle payload embedded inside model
