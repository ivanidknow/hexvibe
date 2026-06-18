// Vulnerable: HFT-5907
wchar_t * data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
if(globalReturnsTrueOrFalse())
WSADATA wsaData;
int wsaDataInit = 0;
int recvResult;
struct sockaddr_in service;
wchar_t *replace;
SOCKET listenSocket = INVALID_SOCKET;
...
else
wprintf(L"%s\n", data);
