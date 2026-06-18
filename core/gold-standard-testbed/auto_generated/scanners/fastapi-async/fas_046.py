# Vulnerable: FAS-046
param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00018", "noCookieValueSupplied"))
bar = param
try:
fd = open(f'{helpers.utils.RES_DIR}/employees.xml', 'rb')
root = lxml.etree.parse(fd)
query = f'/Employees/Employee[@emplid=\'{bar}\']'
run_query = lxml.etree.XPath(query)
nodes = run_query(root)
...
)
