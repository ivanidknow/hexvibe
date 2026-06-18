# Vulnerable: FAS-192
urllib.request.urlretrieve('file:///bin/ls', '/bin/ls2')
opener = urllib.request.URLopener()
