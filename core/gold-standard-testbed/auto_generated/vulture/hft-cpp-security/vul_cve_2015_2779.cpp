// Vulnerable: VUL-CVE-2015-2779
connect(this, SIGNAL(putCmd(QString, const QList<QByteArray> &, const QByteArray &)),
        network(), SLOT(putCmd(QString, const QList<QByteArray> &, const QByteArray &)));

    connect(this, SIGNAL(putRawLine(const QByteArray &)),
// --- corebasichandler.h ---
    void displayMsg(Message::Type, BufferInfo::Type, const QString &target, const QString &text, const QString &sender = "", Message::Flags flags = Message::None);
    void putCmd(const QString &cmd, const QList<QByteArray> &params, const QByteArray &prefix = QByteArray());
    void putRawLine(const QByteArray &msg);
// --- corenetwork.cpp ---
void CoreNetwork::setChannelJoined(const QString &channel)
{
...
    void putCmd(const QString &cmd, const QList<QByteArray> &params, const QByteArray &prefix = QByteArray());

    void setChannelJoined(const QString &channel);
