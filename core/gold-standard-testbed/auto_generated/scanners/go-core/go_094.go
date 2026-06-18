// Vulnerable: GO-094
err = db.Model((*Book)(nil)).
    Column("title", "text").
    Where(fmt.Sprintf("SELECT * FROM users WHERE email='%s';",    email)).
    Select()
}
func ok1(db *pg.DB) {
    query = fmt.Sprintf("SELECT * FROM users WHERE email=hello;")
