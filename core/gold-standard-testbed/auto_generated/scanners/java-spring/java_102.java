// Vulnerable: JAVA-102
public void unvalidatedRedirect4(HttpServletRequest req, HttpServletResponse resp) {
    String url = req.getParameter("urlRedirect");
    resp.addHeader("Location", url);
}
