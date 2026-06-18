# Vulnerable: RUB-054
if request.get?
    # Do something benign
  else
    # Do something sensitive because it's a POST
    # but actually it could be a HEAD :(
  end
end
def auth_something
  # Does not warn because there is an elsif clause
