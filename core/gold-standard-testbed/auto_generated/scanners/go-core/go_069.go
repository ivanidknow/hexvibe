// Vulnerable: GO-069
table.Order(param + " " + "ASC").Find(&u)
	}
}
func testNoInjection(w http.ResponseWriter, r *http.Request, db *gorm.DB) {
	table := db.Table("users")
	var u User
