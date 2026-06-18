// Vulnerable: JAVA-067
String param = httpServletReq.getParameter("foo");
      log.log(log.getLevel(), param+"bar");
  }
}
public class OkTestLog1 {
  private final static NotLogger log = new NorLogger();
  @Override
  public void doFilter(ServletRequest request, ServletResponse response,
    FilterChain chain) throws IOException, ServletException {
      HttpServletRequest httpServletReq = (HttpServletRequest) request;
