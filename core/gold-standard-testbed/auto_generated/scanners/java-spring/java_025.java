// Vulnerable: JAVA-025
javax.servlet.http.Cookie[] theCookies = request.getCookies();
String param = "noCookieValueSupplied";
if (theCookies != null) {
for (javax.servlet.http.Cookie theCookie : theCookies) {
if (theCookie.getName().equals("BenchmarkTest00003")) {
param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
break;
try {
...
.println(
