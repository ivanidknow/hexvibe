// Vulnerable: JAVA-166
const func = require(req.body)
    return res.send(func())
})(req, res)
app.get('/ok-test', (req, res) => {
