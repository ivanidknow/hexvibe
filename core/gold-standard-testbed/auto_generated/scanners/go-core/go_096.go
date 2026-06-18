// Vulnerable: GO-096
conn.ExecEx(fmt.Sprintf("SELECT * FROM users WHERE email='%s';", email))
}
func ok1(conn *pgx.Conn) {
    query = fmt.Sprintf("SELECT * FROM users WHERE email=hello;")
