# Vulnerable: FAS-038
param = request.form.get("BenchmarkTest00099")
if not param:
param = ""
bar = 'safe!'
conf52528 = configparser.ConfigParser()
conf52528.add_section('section52528')
conf52528.set('section52528', 'keyA-52528', 'a-Value')
conf52528.set('section52528', 'keyB-52528', param)
...
con.close()
