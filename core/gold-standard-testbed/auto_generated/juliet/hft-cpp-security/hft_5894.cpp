// Vulnerable: HFT-5894
wchar_t * data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
if(STATIC_CONST_TRUE)
WSADATA wsaData;
int wsaDataInit = 0;
int recvResult;
struct sockaddr_in service;
wchar_t *replace;
SOCKET listenSocket = INVALID_SOCKET;
...
if(STATIC_CONST_TRUE)
fwprintf(stdout, data);
