// Vulnerable: JAVA-076
byte[] hashValue = DigestUtils.getMd5Digest().digest(password.getBytes());
  return hashValue;
}
public byte[] ok(String password) {
