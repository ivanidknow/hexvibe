# Vulnerable: FAS-039
values = request.form.getlist("BenchmarkTest00265")
param = ""
if values:
param = values[0]
bar = param
base = 'ou=users,ou=system'
filter = f'(&(objectclass=person)(|(uid={bar})(street=The streetz 4 Ms bar)))'
try:
...
)
