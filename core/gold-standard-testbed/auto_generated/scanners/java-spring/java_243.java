// Vulnerable: JAVA-243
KeyGenerator keyGen = KeyGenerator.getInstance("AES");
SecretKey key = keyGen.generateKey();
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
byte [] bytes = "abcde".getBytes();
IvParameterSpec ivSpec = new IvParameterSpec(bytes);
cipher.init(Cipher.ENCRYPT_MODE,key,ivSpec);
