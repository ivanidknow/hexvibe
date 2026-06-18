// Vulnerable: JAVA-096
argList.add("echo " + bar);
        // deepruleid: tainted-cmd-from-http-request
        ProcessBuilder pb = new ProcessBuilder(argList);
        try {
            // deepruleid: tainted-cmd-from-http-request
            Process p = pb.start();
            org.owasp.benchmark.helpers.Utils.printOSCommandResults(p, response);
        } catch (IOException e) {
            System.out.println(
                    "Problem executing cmdi - java.lang.ProcessBuilder(java.util.List) Test Case");
...
            argList.add("-c");
        }
