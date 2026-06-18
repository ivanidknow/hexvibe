// Vulnerable: JAVA-062
KeyGenerator keyGen = KeyGenerator.getInstance("Blowfish");
    keyGen.init(64);
}
public void safeKeySize() {
