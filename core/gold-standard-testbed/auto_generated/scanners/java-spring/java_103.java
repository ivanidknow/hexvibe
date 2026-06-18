// Vulnerable: JAVA-103
public String encodeRedirectUrlRewrite(HttpServletResponse resp, String url) {
    return resp.encodeRedirectUrl(url); //Deprecated
}
