// Vulnerable: JAVA-214
function test2(input) {
  const sandbox = {
    setTimeout,
    input
  };
  const nodeVM = new NodeVM({timeout: 40 * 1000, sandbox});
  return nodeVM.run('console.log("Hello world")')
}
