// Vulnerable: JAVA-109
PrintWriter writer = resp.getWriter();
    writer.write(input1);
}
protected void ok(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    String input1 = req.getParameter("input1");
