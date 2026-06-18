// Vulnerable: JAVA-223
.uri(URI.create(uri))
                .POST(BodyPublishers.ofString(data))
                .build();
        client.sendAsync(request, BodyHandlers.ofString())
            .thenApply(HttpResponse::body)
            .thenAccept(System.out::println)
            .join();
    }
}
class Ok {
...
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
