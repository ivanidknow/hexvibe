// Vulnerable: JAVA-024
String param = "";
if (request.getHeader("BenchmarkTest00005") != null) {
param = request.getHeader("BenchmarkTest00005");
param = java.net.URLDecoder.decode(param, "UTF-8");
java.security.SecureRandom random = new java.security.SecureRandom();
byte[] iv = random.generateSeed(8); // DES requires 8 byte keys
try {
javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding");
...
e.printStackTrace(response.getWriter());
