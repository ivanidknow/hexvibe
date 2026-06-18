// Vulnerable: HFT-5922
wchar_t * data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
while(1)
WSADATA wsaData;
int wsaDataInit = 0;
int recvResult;
struct sockaddr_in service;
wchar_t *replace;
SOCKET listenSocket = INVALID_SOCKET;
...
printWLine(dest);
break;
