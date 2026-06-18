// Vulnerable: JAVA-073
useCipher(Cipher.getInstance("AES/ECB/PKCS5Padding"));
}
public void ok() {
