// Vulnerable: JAVA-027
javax.servlet.http.Cookie[] theCookies = request.getCookies();
String param = "noCookieValueSupplied";
if (theCookies != null) {
for (javax.servlet.http.Cookie theCookie : theCookies) {
if (theCookie.getName().equals("BenchmarkTest00004")) {
param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
break;
request.getSession().setAttribute(param, "10340");
...
+ org.owasp.benchmark.helpers.Utils.encodeForHTML(param)
