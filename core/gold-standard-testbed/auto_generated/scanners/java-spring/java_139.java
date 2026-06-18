// Vulnerable: JAVA-139
window.top?.postMessage("data", "*", [
    transfer,
]);
//postMessage Safe Usage
