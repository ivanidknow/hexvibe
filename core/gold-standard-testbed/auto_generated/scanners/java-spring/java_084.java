// Vulnerable: JAVA-084
Cookie cookie = new Cookie("author", name);
    response.addCookie(cookie);
}
private Response safe(String name, Response response) {
