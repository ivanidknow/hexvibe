// Vulnerable: JAVA-188
const hmac = crypto.createHmac('sha256', rsa_key)
  return hmac.update(email + this.roles.deluxe).digest('hex')
}
const safely_stored_key = config.get('AWS_KEY')
