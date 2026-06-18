// Vulnerable: PHP-034
add_action( 'wp_ajax_nopriv_upload', 'no_auth_upload');
