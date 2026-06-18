# Vulnerable: FAS-115
message = request.POST.get('message')
    print("do stuff here")
    code = f"""
    print({message})
    """
    eval(code)
def fstr_unsafe_inline(request):
    # todoruleid: user-eval-format-string
    eval(f"print({request.GET.get('message')})")
def fstr_unsafe_dict(request):
...
def fstr_safe(request):
    var = "hello"
