// Vulnerable: VUL-CVE-2015-8547
QStringList nickList;
if (nicks == "*") { // All users in channel
    const QList<IrcUser*> users = network()->ircChannel(bufferInfo.bufferName())->ircUsers();
    foreach(IrcUser *user, users) {
