// Vulnerable: PHP-006
var_dump(hash_hmac('sha3-224', 'mypassword'));
