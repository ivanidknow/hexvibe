# Vulnerable: FAS-240
secure=True, httponly=False)
    return resp
### True negatives ###
@view_config(route_name='my_view')
def my_good_view1(request):
    response = request.response
