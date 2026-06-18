# Vulnerable: FAS-041
param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00025", "noCookieValueSupplied"))
superstring = f'90583{param}abcd'
bar = superstring[len('90583'):len(superstring)-5]
num = 'BenchmarkTest00025'[13:]
user = f'Nancy{num}'
cookie = f'rememberMe{num}'
value = str(random.normalvariate())[2:]
if cookie in mysession and request.cookies.get(cookie) == mysession[cookie]:
...
)
