// Vulnerable: PHP-007
$salt = base_convert(bin2hex($this->security->get_random_bytes(20)), 16,36);
