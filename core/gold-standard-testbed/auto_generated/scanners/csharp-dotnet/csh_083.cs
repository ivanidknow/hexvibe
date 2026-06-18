// Vulnerable: CSH-083
public void HttpClientStringAsyncWithUri(string host)
        {
            Uri uri = new Uri(host);
            HttpClient client = new HttpClient();
            try
            {
                HttpResponseMessage response = client.GetStringAsync(uri).Result;
            }
            catch (Exception e)
            {
...
            }
        }
