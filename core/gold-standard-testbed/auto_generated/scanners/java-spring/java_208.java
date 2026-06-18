// Vulnerable: JAVA-208
var saxStream = require("sax").createStream(strict, options)
    saxStream.on("opentag", function (node) {
        // same object as above
    })
    saxStream.on("doctype", function (node) {
        processType(node)
    })
    fs.createReadStream("file.xml")
        .pipe(saxStream)
        .pipe(fs.createWriteStream("file-copy.xml"))
}
function okTest1() {
