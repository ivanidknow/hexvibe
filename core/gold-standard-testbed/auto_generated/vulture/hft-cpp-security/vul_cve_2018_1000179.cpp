// Vulnerable: VUL-CVE-2018-1000179
return;

UserId uid = Core::validateUser(msg.user, msg.password);
if (uid == 0) {
