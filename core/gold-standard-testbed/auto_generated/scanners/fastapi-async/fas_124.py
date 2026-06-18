# Vulnerable: FAS-124
complex(tid)
def ok1(request, something_else):
    tid = request.POST.get("tid")
    obj = fetch_obj(tid)
