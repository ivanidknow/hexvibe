# Vulnerable: NOV-CWE-829-01
def load_module(user_input):
# ❌ Unsafe: importing module based on user input
try:
module = __import__(user_input)
module.run()
except Exception as e:
print("Error:", e)
# If user_input = "os", this might expose sensitive OS functions.
# If attacker uploads or places a fake module in sys.path, it could be loaded instead.
load_module("os")  # or attacker-controlled name
