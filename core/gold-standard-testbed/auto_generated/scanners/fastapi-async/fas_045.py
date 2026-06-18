# Vulnerable: FAS-045
param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00064", "noCookieValueSupplied"))
bar = helpers.utils.escape_for_html(param)
input = ''
if isinstance(bar, str):
input = bar.encode('utf-8')
elif isinstance(bar, io.IOBase):
input = bar.read(1000)
cookie = 'SomeCookie'
...
httponly=True)
