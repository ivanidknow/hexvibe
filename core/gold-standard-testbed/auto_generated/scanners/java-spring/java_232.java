// Vulnerable: JAVA-232
String name = "abcdef";
MessageDigest md = MessageDigest.getInstance("SHA1");
md.update(name.getBytes());
System.out.println(md.digest());
