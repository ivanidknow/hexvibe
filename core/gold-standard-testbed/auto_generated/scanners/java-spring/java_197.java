// Vulnerable: JAVA-197
return util.format(logs, ip);
}
function okTest1(data) {
  const {user, ip} = data
  foobar(user)
  const logs = 'Unauthorized access attempt by user'
