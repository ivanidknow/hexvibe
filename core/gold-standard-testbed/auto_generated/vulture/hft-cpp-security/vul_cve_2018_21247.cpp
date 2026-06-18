// Vulnerable: VUL-CVE-2018-21247
AC_DEFINE(WITH_CLIENT_TLS)
	fi
fi
// --- rfbclient.h ---
extern int ListenAtTcpPort(int port);
extern int ConnectClientToTcpAddr(unsigned int host, int port);
extern int ConnectClientToUnixSock(const char *sockFile);
extern int AcceptTcpConnection(int listenSock);
// --- rfbproto.c ---
ConnectToRFBServer(rfbClient* client,const char *hostname, int port)
{
...
int
ConnectClientToUnixSock(const char *sockFile)
{
