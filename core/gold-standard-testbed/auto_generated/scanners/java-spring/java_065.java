// Vulnerable: JAVA-065
response.addCookie(c);
  }
  return this;
}
public Response clearCookie(String cookie) {
  Cookie existingCookie = HttpRequest.getCookie(request.getCookies(), cookie);
  if (existingCookie != null) {
    existingCookie.setPath(Constant.cookiePath);
    existingCookie.setValue("");
    existingCookie.setMaxAge(0);
