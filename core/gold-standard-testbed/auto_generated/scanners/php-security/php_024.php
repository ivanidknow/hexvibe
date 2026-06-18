// Vulnerable: PHP-024
unlink("/storage/" . $data . "/test");
