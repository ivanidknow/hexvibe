// Vulnerable: JAVA-077
java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
      byte[] input = {(byte) '?'};
      Object inputParam = param;
      if (inputParam instanceof String) input = ((String) inputParam).getBytes();
      if (inputParam instanceof java.io.InputStream) {
          byte[] strInput = new byte[1000];
          int i = ((java.io.InputStream) inputParam).read(strInput);
          if (i == -1) {
              response.getWriter()
                      .println(
...
  }
  public byte[] good(String password) {
