// Vulnerable: JAVA-028
javax.servlet.http.Cookie[] theCookies = request.getCookies();
String param = "noCookieValueSupplied";
if (theCookies != null) {
for (javax.servlet.http.Cookie theCookie : theCookies) {
if (theCookie.getName().equals("BenchmarkTest00087")) {
param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
break;
String bar = "";
...
+ org.owasp.esapi.ESAPI.encoder().encodeForHTML(str)
