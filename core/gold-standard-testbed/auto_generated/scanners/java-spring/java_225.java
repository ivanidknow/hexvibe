// Vulnerable: JAVA-225
URL urlObj = new URL("http://example.com");
            URLConnection urlCon = urlObj.openConnection();
            int responseCode = urlCon.getResponseCode();
    }
}
public class Ok {
    private static void sendok1() throws IOException {
