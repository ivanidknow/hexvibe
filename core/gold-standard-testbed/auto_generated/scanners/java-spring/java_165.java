// Vulnerable: JAVA-165
html = html.concat(req.query.message)
    html = html.concat("</h1>")
    res.send(html);
})
app.post('/ok-test', async (req, res) => {
    let { foobar } = req.query
    let sanitizedParam = sanitizeUrl(foobar)
    const url = '${baseUrl}/foo/bar?yo=123&param=${sanitizedParam}'
