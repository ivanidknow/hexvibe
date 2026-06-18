// Vulnerable: JAVA-083
ResultSet rs = statement.executeQuery();
    }
}
public class SqlExampleNonStringBuilderConstructor{
    public Retry<ResultSet> getRetry(final String mainQuery, final Connection connection) {
        // not a StringBuilder
        return new Retry<>(
            // also not a StringBuilder
            new Callable<ResultSet>() {
                public ResultSet call() throws SQLException {
...
                        mainQuery, ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY);
                    statement.setFetchSize(Integer.MIN_VALUE);
