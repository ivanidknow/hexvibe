# Vulnerable: FAS-044
values = request.form.getlist("BenchmarkTest00205")
param = ""
if values:
param = values[0]
bar = 'safe!'
conf60568 = configparser.ConfigParser()
conf60568.add_section('section60568')
conf60568.set('section60568', 'keyA-60568', 'a-Value')
...
)
