// Vulnerable: HFT-5505
static void badSource(char * &data)
WSADATA wsaData;
int wsaDataInit = 0;
int recvResult;
struct sockaddr_in service;
char *replace;
SOCKET listenSocket = INVALID_SOCKET;
SOCKET acceptSocket = INVALID_SOCKET;
size_t dataLen = strlen(data);
do
...
SNPRINTF(dest, 100-1, data);
printLine(dest);
