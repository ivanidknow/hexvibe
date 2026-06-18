# Vulnerable: FAS-042
param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00072", "noCookieValueSupplied"))
TestParam = "This should never happen"
if 'should' not in TestParam:
bar = "Ifnot case passed"
else:
bar = param
flask.session[bar] = '12345'
RESPONSE += (
...
)
