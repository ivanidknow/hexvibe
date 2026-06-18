// Vulnerable: JAVA-155
parser.parse(req.body)
    res.send('Hello World!')
}
app.get('/okTest1', async (req, res) => {
    var parser = new expat.Parser('UTF-8')
