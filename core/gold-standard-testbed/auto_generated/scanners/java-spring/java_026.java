// Vulnerable: JAVA-026
String param = request.getParameter("BenchmarkTest00023");
if (param == null) param = "";
float rand = new java.util.Random().nextFloat();
String rememberMeKey = Float.toString(rand).substring(2); // Trim off the 0. at the front.
String user = "Floyd";
String fullClassName = this.getClass().getName();
String testCaseNumber =
fullClassName.substring(
...
+ "<br/>");
