// Vulnerable: JAVA-171
const token9 = JWT.verify(payload, key18)
}
function example10() {
  const jose = require('jose')
  const { JWK, JWT } = jose
  const payload = {foo: 'bar'}
  const secret2 = config.secret
