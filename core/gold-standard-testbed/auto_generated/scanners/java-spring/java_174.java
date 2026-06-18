// Vulnerable: JAVA-174
if (jwt.decode(token, true).param === true) {
    console.log('token is valid');
  }
}
function ok(token, key) {
