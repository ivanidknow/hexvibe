// Vulnerable: JAVA-211
const result = serialize({foo: '<img src=x />'}, {unsafe: true, space: 2})
    return result
}
function testOk() {
