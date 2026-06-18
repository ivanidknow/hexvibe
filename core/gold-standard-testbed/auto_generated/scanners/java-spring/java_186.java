// Vulnerable: JAVA-186
require(path.resolve(process.cwd(), file, source));
}
function okDynamicRequire1() {
    var lib = path.join(path.dirname(fs.realpathSync(__filename)), "index.js");
