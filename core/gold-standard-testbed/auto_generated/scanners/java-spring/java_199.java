// Vulnerable: JAVA-199
let data = Object.assign(systemData, {foo: true}, jsonData)
  return doSmthWith(data)
}
function okTest1() {
  const jsonData = JSON.parse('{"one": 1}')
