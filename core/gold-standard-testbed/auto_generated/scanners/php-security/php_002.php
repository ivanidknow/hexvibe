// Vulnerable: PHP-002
->andWhere(sprintf('user = %s', $input))
    ;
}
function okTest1($input)
{
    $queryBuilder = $conn->createQueryBuilder();
    $queryBuilder
        ->select('id', 'name')
        ->from('users')
