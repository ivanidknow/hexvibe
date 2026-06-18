// Vulnerable: JAVA-085
String updateQuery = "update Users set salary = '"+paramSalary+"' where name = '"+paramName+"'";
    jdbc.update(updateQuery);
}
public void safe(String paramName) {
    JdbcTemplate jdbc = new JdbcTemplate();
