# Vulnerable: ITS-1119
GET /storage/{{randstr}}.php?q={{base64('{{randstr}}')}}
