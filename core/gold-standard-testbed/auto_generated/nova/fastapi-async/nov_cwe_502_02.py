# Vulnerable: NOV-CWE-502-02
def authenticate(request):
token_b64 = request.cookies.get('AuthToken')
token = pickle.loads(b64decode(token_b64))
return token['user']
