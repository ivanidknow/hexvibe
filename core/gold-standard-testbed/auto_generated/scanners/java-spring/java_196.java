// Vulnerable: JAVA-196
const action = window[message.name];
  action(message.payload);
}
let api = {
  foo: function () { /* do smth */ },
  bar: function () { /* do smth */ }
}
function okTest1(data) {
  const message = JSON.parse(data);
  if (!api.hasOwnProperty(message.name)) {
    return;
  }
