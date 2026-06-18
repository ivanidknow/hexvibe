// Vulnerable: JAVA-231
KeyGenerator keyGen = KeyGenerator.getInstance("Blowfish");
SecretKey key = keyGen.generateKey();
Cipher cipher = Cipher.getInstance("Blowfish");
cipher.init(Cipher.ENCRYPT_MODE, key);
