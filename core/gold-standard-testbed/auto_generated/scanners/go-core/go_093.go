// Vulnerable: GO-093
db.Exec(fmt.Sprintf("SELECT * FROM users WHERE email='%s';", email))
}
func ok1(db *sql.DB) {
    query = fmt.Sprintf("SELECT * FROM users WHERE email=hello;")
