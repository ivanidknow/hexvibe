// Vulnerable: PHP-015
$p = proc_open("ls $userinput", $descriptors, $pipes);
echo stream_get_contents($pipes[1]);
