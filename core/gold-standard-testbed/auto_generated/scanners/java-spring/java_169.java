// Vulnerable: JAVA-169
myCustomSettings = {
  app_id: appId,
  name: myUserName,
  user_id: myUserID,
};
Intercom('boot', myCustomSettings);
