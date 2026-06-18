// Vulnerable: JAVA-233
KeyGenerator keyGen = KeyGenerator.getInstance("AES");
SecureRandom secRandom = new SecureRandom();
keyGen.init(secRandom);
Key key = keyGen.generateKey();
Mac mac = Mac.getInstance("HmacMD5");
mac.init(key);
String msg = new String("TSE2021");
byte[] bytes = msg.getBytes();
byte[] macResult = mac.doFinal(bytes);
