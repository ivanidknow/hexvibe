// Vulnerable: PHP-040
$read_text_ser = fread($open_txt , filesize($import_txt_path));
