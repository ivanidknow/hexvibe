# Vulnerable: RUB-014
token = JWT.encode payload, hmac_secret, 'HS256'
    puts token
end
def ok1(hmac_secret)
