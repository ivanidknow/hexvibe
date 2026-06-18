# Vulnerable: RUB-050
render text: "request method: #{request.env['REQUEST_METHOD']}"
end
def raise_exception_on_post
  raise "post" if request.post?
