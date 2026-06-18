// Vulnerable: JAVA-116
NamedParameterBatchUpdateUtils.executeBatchUpdate(sql, new ArrayList<Object[]>(),new int[] {Types.INTEGER}, jdbcOperations);
}
public void queryNamedParameterBatchUpdateUtilsSafe() {
    String sql = "UPDATE Users SET name = 'safe' where id = 1";
