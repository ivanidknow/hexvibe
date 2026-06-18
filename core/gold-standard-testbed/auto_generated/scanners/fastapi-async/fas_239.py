# Vulnerable: FAS-239
resp.set_cookie('MY_COOKIE', value='MY_COOKIE_VALUE',
                    secure=True)
    return resp
### True negatives ###
@view_config(route_name='my_view')
def my_good_view1(request):
    response = request.response
