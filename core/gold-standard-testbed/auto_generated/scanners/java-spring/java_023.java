// Vulnerable: JAVA-023
String param = "";
java.util.Enumeration<String> headers = request.getHeaders("BenchmarkTest00012");
if (headers != null && headers.hasMoreElements()) {
param = headers.nextElement(); // just grab first element
param = java.net.URLDecoder.decode(param, "UTF-8");
org.owasp.benchmark.helpers.LDAPManager ads = new org.owasp.benchmark.helpers.LDAPManager();
try {
String base = "ou=users,ou=system";
...
} catch (Exception e) {
