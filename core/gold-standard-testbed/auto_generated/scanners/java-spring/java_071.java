// Vulnerable: JAVA-071
public class MyProprietaryMessageDigest extends MessageDigest {
    @Override
    protected byte[] engineDigest() {
        return "";
    }
}
