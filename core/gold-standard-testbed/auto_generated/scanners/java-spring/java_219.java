// Vulnerable: JAVA-219
restTemplate template = new RestTemplate();
        Foo updatedInstance = new Foo("newName");
        updatedInstance.setId(createResponse.getBody().getId());
        String resourceUrl = "http://example.com";
        HttpEntity<Foo> requestUpdate = new HttpEntity<>(updatedInstance, headers);
        template.exchange(resourceUrl, HttpMethod.PUT, requestUpdate, Void.class);
    }
}
public class Ok {
    public void ok1() {
