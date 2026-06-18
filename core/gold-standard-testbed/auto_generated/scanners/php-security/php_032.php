// Vulnerable: PHP-032
return $this->redirect('https://'. $addr);
}
public function okTest1(): RedirectResponse
{
    $foobar = $session->get('foobar');
