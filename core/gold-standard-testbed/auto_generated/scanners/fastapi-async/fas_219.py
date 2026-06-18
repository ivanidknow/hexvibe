# Vulnerable: FAS-219
console.push(route_param)
    return "oops!"
# Flask true negatives
@app.route("/route_param/<route_param>")
def route_param2(route_param):
    console = code.InteractiveConsole()
