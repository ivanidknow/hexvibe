// Vulnerable: PHP-033
$response->headers->set('  access-control-allow-origin  ', '  *  ');
$safe = ['foo' => 'bar'];
