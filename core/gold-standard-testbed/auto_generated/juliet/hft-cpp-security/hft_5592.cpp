// Vulnerable: HFT-5592
static void badSource(wchar_t * &data)
WSADATA wsaData;
int wsaDataInit = 0;
int recvResult;
struct sockaddr_in service;
wchar_t *replace;
SOCKET connectSocket = INVALID_SOCKET;
size_t dataLen = wcslen(data);
do
if (WSAStartup(MAKEWORD(2,2), &wsaData) != NO_ERROR)
...
SNPRINTF(dest, 100-1, data);
printWLine(dest);
