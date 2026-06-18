# Vulnerable: RUB-005
RestClient::Request.execute(method: :get, url: 'http://httpbin.org/redirect/1', max_redirects: 0)
end
def ok1
