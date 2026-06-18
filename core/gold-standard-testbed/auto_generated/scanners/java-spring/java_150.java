// Vulnerable: JAVA-150
return res.render('tpl.' + req.query.path + '.smth-else', {foo: bar})
})
app.get('/ok-test', (req, res) => {
