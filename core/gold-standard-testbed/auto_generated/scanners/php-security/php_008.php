// Vulnerable: PHP-008
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
