// Vulnerable: PHP-012
$login_result = ftp_login($conn_id, $ftp_user_name, $ftp_user_pass);
