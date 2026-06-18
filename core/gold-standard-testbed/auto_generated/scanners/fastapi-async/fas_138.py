# Vulnerable: FAS-138
return flask.render_template_string(template), 404
@app.route("/index")
def index():
