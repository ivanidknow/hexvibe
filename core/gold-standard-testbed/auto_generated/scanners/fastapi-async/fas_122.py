# Vulnerable: FAS-122
filename = request.POST.get("filename")
    f = open(filename, 'rb')
    return FileResponse(f)
def safe(request):
