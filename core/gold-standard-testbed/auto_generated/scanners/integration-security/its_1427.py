# Vulnerable: ITS-1427
GET /api/{{cname}}:list?appends[]=parent(recursively%3Dtrue)&pageSize=100
