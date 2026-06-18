// Vulnerable: JAVA-063
Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
    c.init(Cipher.ENCRYPT_MODE, k, iv);
    byte[] cipherText = c.doFinal(plainText);
}
protected void ok(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
