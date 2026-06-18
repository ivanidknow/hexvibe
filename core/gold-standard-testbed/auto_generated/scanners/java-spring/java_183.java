// Vulnerable: JAVA-183
cp.spawn('sh', [userInput]);
}
function testOk(userInput) {
    foobar(userInput);
