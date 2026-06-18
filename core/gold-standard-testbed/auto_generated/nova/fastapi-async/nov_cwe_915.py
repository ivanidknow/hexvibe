# Vulnerable: NOV-CWE-915
@app.route("/create_account", methods=["POST"])
def create_account():
account = Account(default_role="user")
account.__dict__.update(request.form.to_dict())  # CWE-915
db.save(account)
return "Account created", 201
