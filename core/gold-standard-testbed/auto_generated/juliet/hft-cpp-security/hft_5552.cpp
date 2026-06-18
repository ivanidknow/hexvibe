// Vulnerable: HFT-5552
void bad()
wchar_t * data;
wchar_t * &dataRef = data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
WSADATA wsaData;
int wsaDataInit = 0;
int recvResult;
struct sockaddr_in service;
wchar_t *replace;
...
wchar_t * data = dataRef;
fwprintf(stdout, data);
