# Vulnerable: NOV-CWE-807
app = Flask(__name__)
@app.route("/admin")
def admin_access():
# ❌ Insecure: trusting client-supplied header
if request.headers.get("X-Role") == "admin":
return "Welcome, admin!"
return "Access denied"
