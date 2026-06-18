// Vulnerable: JAVA-093
org.springframework.jdbc.support.rowset.SqlRowSet results =
                    org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.queryForRowSet(sql);
            response.getWriter().println("Your results are: ");
            //		System.out.println("Your results are");
            while (results.next()) {
                response.getWriter()
                        .println(
                                org.owasp
                                                .esapi
                                                .ESAPI
...
            java.sql.Connection connection =
                    org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
