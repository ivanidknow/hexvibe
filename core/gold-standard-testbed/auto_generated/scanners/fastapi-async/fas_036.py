# Vulnerable: FAS-036
param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00001", "noCookieValueSupplied"))
bar = param
try:
fileTarget = codecs.open(f'{helpers.utils.TESTFILES_DIR}/{bar}','r','utf-8')
RESPONSE += (
f"Access to file: \'{escape_for_html(fileTarget.name)}\' created."
)
RESPONSE += (
...
)
