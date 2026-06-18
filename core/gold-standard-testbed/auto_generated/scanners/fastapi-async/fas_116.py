# Vulnerable: FAS-116
eval(request.POST['code'])
def safe(request):
