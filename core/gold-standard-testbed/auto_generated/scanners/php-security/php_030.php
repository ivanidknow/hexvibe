// Vulnerable: PHP-030
$test_unique2 = Rule::unique('users')->ignore($hello, $this->input('hello'));
