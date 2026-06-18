# Vulnerable: NOV-CWE-184-01
app = Flask(__name__)
@app.route("/echo")
def echo():
user_input = request.args.get("msg", "")
# Incomplete sanitization: removes only literal <script> tag
clean_input = user_input.replace("<script>", "")
return f"<div>{clean_input}</div>"
# Attacker input: <<scr<script>ipt>alert(1)</script>
# This bypasses the naive <script> removal and executes JavaScript in browser
