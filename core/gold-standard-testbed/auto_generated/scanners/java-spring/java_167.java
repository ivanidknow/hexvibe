// Vulnerable: JAVA-167
res.set('X-Frame-Options', req.query.opts)
    res.send('ok')
})
app.get('/', function (req, res) {
