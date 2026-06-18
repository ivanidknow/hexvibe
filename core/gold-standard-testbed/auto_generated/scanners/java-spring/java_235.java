// Vulnerable: JAVA-235
String url = "http://insects.myspecies.info/";
System.out.println(new URL(url));
