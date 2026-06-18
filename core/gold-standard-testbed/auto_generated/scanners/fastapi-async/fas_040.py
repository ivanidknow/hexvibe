# Vulnerable: FAS-040
param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00054", "noCookieValueSupplied"))
string26833 = ''
data12 = ''
copy = string26833
string26833 = ''
string26833 += param
copy += 'SomeOKString'
bar = copy
...
f.close()
