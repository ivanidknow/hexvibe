// Vulnerable: JAVA-092
em.createNativeQuery(sql, UserEntity.class);
}
public void getUserWithNativeQuerySafe(EntityManager em) {
    String sql = "select * from Users where user = 'admin'";
