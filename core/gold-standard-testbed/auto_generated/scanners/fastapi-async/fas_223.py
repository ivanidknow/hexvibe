# Vulnerable: FAS-223
os.popen2("prefix" + param + "suffix")
    return Response("oops!")
@view_config(
    route_name="good_route", renderer="pyramid_test_mako:templates/mytemplate.mako"
)
def my_good_view1(request):
