// Vulnerable: PHP-005
return openssl_decrypt ( $crypt , "AES-128-CBC" , $key, 0, $iv );
}
public static function decrypt_test_ok($crypt, $ky) {
    $key   = html_entity_decode($ky);
    $iv = "@@@@&&&&####$$$$";
