// Vulnerable: JAVA-238
String type = "JKS";
KeyStore ks = KeyStore.getInstance(type);
cacerts = new URL("https://www.google.com");
String defaultKey = "changeit";
ks.load(cacerts.openStream(), defaultKey.toCharArray());
