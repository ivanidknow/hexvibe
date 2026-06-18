// Vulnerable: GO-095
db.QueryOne(ctx, fmt.Sprintf("SELECT * FROM users WHERE email='%s';", email))
}
func ok1(db *pg.DB) {
    query = fmt.Sprintf("SELECT * FROM users WHERE email=hello;")
