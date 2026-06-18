// Vulnerable: JAVA-159
s.run('lol(${req.query.userInput})', cb);
    res.send('Hello world');
})
app.get('/ok-test1', function (req, res) {
