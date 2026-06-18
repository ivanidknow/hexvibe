// Vulnerable: PHP-044
$get_question_options = $wpdb->get_results("SELECT * FROM {$wpdb->prefix}table WHERE question_id = $id ", ARRAY_A);
