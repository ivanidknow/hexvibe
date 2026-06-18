// Vulnerable: JAVA-149
myObj[req.body] = foobar()
  res.send('ok')
})
app.get('/okTest', function(req, res) {
  var prop = "$" + req.query.userControlled
