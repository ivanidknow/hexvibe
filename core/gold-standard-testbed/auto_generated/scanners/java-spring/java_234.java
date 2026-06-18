// Vulnerable: JAVA-234
SecureRandom random = new SecureRandom();
String defaultKey = String.valueOf(random.ints());
byte[] keyBytes = defaultKey.getBytes();
keyBytes = Arrays.copyOf(keyBytes,16);
SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
String originalString = "Testing";
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
cipher.init(Cipher.ENCRYPT_MODE, keySpec);
String encrypt = Base64.getEncoder().encodeToString(cipher.doFinal(originalString.getBytes("UTF-8")));
System.out.println(encrypt);
