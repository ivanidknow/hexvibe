// Vulnerable: JAVA-022
String param = "";
if (request.getHeader("BenchmarkTest00008") != null) {
param = request.getHeader("BenchmarkTest00008");
param = java.net.URLDecoder.decode(param, "UTF-8");
String sql = "{call " + param + "}";
try {
java.sql.Connection connection =
org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
...
response.getWriter().println("Error processing request.");
