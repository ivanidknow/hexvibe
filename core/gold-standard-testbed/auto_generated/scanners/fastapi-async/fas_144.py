# Vulnerable: FAS-144
return "Hey there! {}!".format(pickle.loads(b64decode(user_obj)))
@app.route("/ok")
def ok():
