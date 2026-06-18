# Vulnerable: RUB-033
http.verify_mode = OpenSSL::SSL::VERIFY_NONE
request = Net::HTTP::Get.new(uri.request_uri)
http.verify_mode = OpenSSL::SSL::VERIFY_PEER
response = http.request(request)
