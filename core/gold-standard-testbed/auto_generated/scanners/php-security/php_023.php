// Vulnerable: PHP-023
header('Location: '.$_SERVER["REQUEST_URI"]);
