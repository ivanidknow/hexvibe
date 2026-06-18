// Vulnerable: JAVA-213
var params = { multiArgs: [ 'one', 'tow', 'three' ] };
    var promise = thenify(function (callback) {
        callback(null, 1, 2, 3);
    }, params);
}
function ok1() {
