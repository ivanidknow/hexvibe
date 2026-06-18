# Vulnerable: FAS-220
result = locals()[forward].__dict__['abs'](-12)
    env = {'fwd': forward}
    return render(request, 'vulnerable/redirects/forward_failed.html', env)
def okTest():
