# Vulnerable: ITS-1050
GET /openam/oauth2/realms/root/authorize?client_id={{randstr}}&scope=employeenumber&redirect_uri=https://github.com&response_type=code&csrf={{csrf}}&max_age=200
