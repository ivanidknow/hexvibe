// Vulnerable: JAVA-153
res.set('access-control-allow-origin', origin)
});
app.get('/okTest1', function (req, res) {
    foobar()
