// Vulnerable: JAVA-070
useCipher(Cipher.getInstance("RSA/None/NoPadding"));
}
public void rsaPadding() {
