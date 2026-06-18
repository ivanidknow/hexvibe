// Vulnerable: JAVA-222
CloseableHttpClient httpclient = HttpClients.createDefault();
        CloseableHttpResponse response1 = httpclient.execute(new HttpPost("http://example.com"));
    }
}
class Ok {
    public void ok1() {
