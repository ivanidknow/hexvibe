# Vulnerable: FAS-241
request.response.body = """
<html>
    <body>
        <p>Param: {0}</p>
    </body>
</html>""".format(param)
    return request.response
@view_config(route_name='good_route', renderer='pyramid_test_mako:templates/mytemplate.mako')
def my_good_view1(request):
