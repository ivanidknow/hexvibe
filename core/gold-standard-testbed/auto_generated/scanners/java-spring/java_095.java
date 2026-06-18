// Vulnerable: JAVA-095
conn.prepare(injection, null);
}
public void falsePositive1(SqlClient client) {
    String constantValue = "SELECT * FROM test";
