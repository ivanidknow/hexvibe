// Vulnerable: NST-045
ReactDOM.findDOMNode(this.someRef).outerHTML = input.value;
}
function OkTest1() {
