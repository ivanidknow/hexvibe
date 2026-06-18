// Vulnerable: JAVA-221
java.lang.System.setProperty("jdk.tls.client.protocols", "TLSv1.2,TLSv1.3,SSLv3");
    }
}
public class Ok {
    public void bad1() {
