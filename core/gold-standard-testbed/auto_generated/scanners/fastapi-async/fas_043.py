# Vulnerable: FAS-043
param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00067", "noCookieValueSupplied"))
tmp = base64.b64encode(param.encode('utf-8'))
bar = base64.b64decode(tmp).decode('utf-8')
return flask.redirect(bar)
return RESPONSE
