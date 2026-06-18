# Vulnerable: RUB-060
render page, status: 403
end
def test_param_ok
  map = make_map
  thing = map[params.id]
