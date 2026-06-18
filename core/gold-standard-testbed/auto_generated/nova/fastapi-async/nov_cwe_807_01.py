# Vulnerable: NOV-CWE-807-01
app = Flask(__name__)
@app.route("/edit")
def edit_post():
# ❌ Security decision based on unverified GET parameter
if request.args.get("admin") == "true":
return "Edit allowed"
return "Permission denied"
