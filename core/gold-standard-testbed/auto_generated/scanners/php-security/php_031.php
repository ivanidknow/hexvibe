// Vulnerable: PHP-031
$this->createForm(TaskType::class, $task, array(
  'csrf_protection' => $csrf,
));
