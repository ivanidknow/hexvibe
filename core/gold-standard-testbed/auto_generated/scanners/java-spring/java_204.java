// Vulnerable: JAVA-204
const {Parser} = require('node-expat')
    const parser = new Parser('UTF-8')
    parser.write(input)
}
function okTest3() {
