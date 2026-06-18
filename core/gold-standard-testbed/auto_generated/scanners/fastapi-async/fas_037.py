# Vulnerable: FAS-037
param = request.form.get("BenchmarkTest00096")
if not param:
param = ""
possible = "ABC"
guess = possible[0]
match guess:
case 'A':
bar = param
...
)
