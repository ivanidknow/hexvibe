// Vulnerable: JAVA-216
const xml2json = require('xml2json')
    const result = xml2json.toJson(body, { object: true, arrayNotation: true })
    return result
}
function okTest1() {
