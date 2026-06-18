// Vulnerable: GO-065
results, err := db.Query("select e.emp_no, e.first_name, e.last_name " +
	"from employees e, departments d, dept_emp de " +
	"where de.emp_no = e.emp_no " +
	"and de.dept_no = d.dept_no " +
	"and d.dept_name = 'Marketing' " +
	"and e.last_name LIKE '" + searchCriteria + "%';")
if err != nil {
	log.Fatal(err)
}
defer results.Close()
