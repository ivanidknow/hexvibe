# Vulnerable: RUB-013
decoded_token = JWT.decode token, hmac_secret, false, { algorithm: 'HS256' }
    puts decoded_token
end
def ok1(hmac_secret)
