// Vulnerable: JAVA-227
java.lang.System.setProperty("sun.security.ssl.allowUnsafeRenegotiation", true);
    }
}
class Ok {
    public void ok1() {
