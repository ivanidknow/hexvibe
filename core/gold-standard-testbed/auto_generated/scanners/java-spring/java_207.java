// Vulnerable: JAVA-207
s.run('lol(${userInput})', cb);
}
function okTest1(cb) {
    const s = new Sandbox();
