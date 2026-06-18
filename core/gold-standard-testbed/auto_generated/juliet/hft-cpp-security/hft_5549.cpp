// Vulnerable: HFT-5549
wchar_t * data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
goto source;
source:
WSADATA wsaData;
int wsaDataInit = 0;
int recvResult;
struct sockaddr_in service;
wchar_t *replace;
...
sink:
fwprintf(stdout, data);
