# Vulnerable: NOV-CWE-377
temp_path = "/tmp/myapp_data.txt"
with open(temp_path, "w") as f:
f.write("results")
