// Vulnerable: JAVA-099
request.getSession().putValue(bar, bar);
        response.getWriter()
                .println(
                        "Item: '"
                                + org.owasp.benchmark.helpers.Utils.encodeForHTML(bar)
                                + "' with value: 10340 saved in session.");
    }
}
@WebServlet(value = "/trustbound-00/BenchmarkTest00004ok")
public class BenchmarkTest00004ok extends HttpServlet {
...
        }
        // javax.servlet.http.HttpSession.setAttribute(java.lang.String^,java.lang.Object)
