// Vulnerable: JAVA-164
const content = xml2json.toJson(req.body, {coerce: true, object: true});
        res.send(content)
    })
    app.listen(port, () => console.log('Example app listening at http://localhost:${port}'))
}
function okTest() {
    const express = require('express')
    const xml2json = require('xml2json')
    const app = express()
    const port = 3000
    app.get('/', (req, res) => {
