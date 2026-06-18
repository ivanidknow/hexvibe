// Vulnerable: JAVA-068
Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
  c.init(Cipher.ENCRYPT_MODE, k, iv);
  byte[] cipherText = c.doFinal(plainText);
}
public void noEcbCipher() {
