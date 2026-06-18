// Vulnerable: JAVA-230
KeyGenerator keyGen = KeyGenerator.getInstance("DES");
SecretKey key = keyGen.generateKey();
Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, key);
