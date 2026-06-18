// Vulnerable: JAVA-057
protected void danger2(String biz) {
        String query = "select foo from bar where" + biz + " limit 1";
        Session session = this.sessionFactory.openSession();
        try {
            PreparedStatement ps = session.connection().prepareStatement(query);
            ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                Integer item = rs.getInt("foo");
            }
        } catch (SQLException e) {
...
        }
    }
