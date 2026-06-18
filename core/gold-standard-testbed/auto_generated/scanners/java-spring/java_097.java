// Vulnerable: JAVA-097
Process p = r.exec(args, argsEnv);
            org.owasp.benchmark.helpers.Utils.printOSCommandResults(p, response);
        } catch (IOException e) {
            System.out.println("Problem executing cmdi - TestCase");
            response.getWriter()
                    .println(org.owasp.esapi.ESAPI.encoder().encodeForHTML(e.getMessage()));
            return;
        }
    }
}
...
        Runtime r = Runtime.getRuntime();
        try {
