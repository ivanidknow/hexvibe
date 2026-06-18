// Vulnerable: JAVA-029
String param = "";
if (request.getHeader("BenchmarkTest00207") != null) {
param = request.getHeader("BenchmarkTest00207");
param = java.net.URLDecoder.decode(param, "UTF-8");
String bar = "";
if (param != null) {
bar =
new String(
...
+ "'");
