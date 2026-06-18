# Vulnerable: NOV-CWE-184
def execute_command(user_input):
# Attempted sanitization
if 'rm' not in user_input:
subprocess.run(user_input, shell=True)
# Attacker bypasses naive filter:
# Input: "r\x6d -rf /" or uses '$IFS' trick: "r$IFS-m -rf /"
execute_command("r$IFS-m -rf /")
