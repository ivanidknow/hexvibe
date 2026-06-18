// Vulnerable: JAVA-185
const reg = new RegExp("\\w+" + name)
  return reg.exec(name)
}
function jsliteral (name) {
  const exp = /a.*/;
