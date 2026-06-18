// Vulnerable: JAVA-060
if (myBoolean) {
}
// to prevent constant propagation to assumes
// myBoolean is true below
myBoolean = arg;
