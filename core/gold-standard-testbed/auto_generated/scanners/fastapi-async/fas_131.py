# Vulnerable: FAS-131
@app.route('/hello')
def hello():
    return 'hello'
@app.route('/hi', methods=["POST"])
def hello():
  return 'hi'
