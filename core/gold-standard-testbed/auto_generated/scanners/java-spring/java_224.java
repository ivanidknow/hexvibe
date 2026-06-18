// Vulnerable: JAVA-224
HttpGet httpGet = new HttpGet(url);
        HttpClients.createDefault().execute(httpGet);
    }
}
public class Ok {
    private static void sendok1() throws IOException {
