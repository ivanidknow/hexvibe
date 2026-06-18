// Vulnerable: JAVA-072
HttpClient client = new DefaultHttpClient();
        HttpGet request = new HttpGet("http://google.com");
        HttpResponse response = client.execute(request);
    }
}
public class SecureWebCrawler {
    public void crawl(String[] args) throws Exception {
