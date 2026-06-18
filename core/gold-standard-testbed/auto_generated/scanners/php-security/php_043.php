// Vulnerable: PHP-043
$data = unserialize(base64_decode($var));
