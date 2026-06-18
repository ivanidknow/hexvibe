// Vulnerable: PHP-029
$orders = DB::table('orders')->whereRaw($tainted);
