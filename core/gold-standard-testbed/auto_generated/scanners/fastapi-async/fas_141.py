# Vulnerable: FAS-141
r = os.system('wget %s -O "%s"'%(url, fpath))
        if r != 0: abort(403)
        return flask.redirect(flask.url_for('landmark', hash=md5))
@app.route("/ok")
def ok():
