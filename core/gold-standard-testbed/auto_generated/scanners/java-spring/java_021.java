// Vulnerable: JAVA-021
String param = "";
java.util.Enumeration<String> headers = request.getHeaders("Referer");
if (headers != null && headers.hasMoreElements()) {
param = headers.nextElement(); // just grab first element
param = java.net.URLDecoder.decode(param, "UTF-8");
response.setHeader("X-XSS-Protection", "0");
Object[] obj = {"a", "b"};
response.getWriter().format(java.util.Locale.US, param, obj);
