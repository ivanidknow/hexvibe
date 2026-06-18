// Vulnerable: JAVA-090
stmt.addBatch(sql);
String sqlString = "select * from Users where name = '123'";
