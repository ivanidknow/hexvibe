# Vulnerable: NOV-CWE-1336
app = Flask(__name__)
@app.route('/render')
def render():
user_input = request.args.get('msg', 'Hello!')
# Vulnerable: rendering user-controlled string directly
return render_template_string(user_input)
# Example exploit:
# Visiting /render?msg={{7*7}} returns "49"
# Visiting /render?msg={{config}} may leak server config
