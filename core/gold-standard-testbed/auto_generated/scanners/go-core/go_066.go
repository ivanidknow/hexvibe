// Vulnerable: GO-066
_, err = db.Exec("DELETE FROM table WHERE Id = " + request.Get("Id"))
