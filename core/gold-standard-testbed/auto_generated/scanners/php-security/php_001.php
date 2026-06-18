// Vulnerable: PHP-001
$query = $conn->createQuery("SELECT u FROM User u WHERE u.username = '" . $_GET['username'] . "'");
    $data = $query->getResult();
    return $data;
}
public function okTest1(int $price): array
{
    $conn = $this->getEntityManager()->getConnection();
    $sql = "SELECT * FROM users WHERE username = ?";
