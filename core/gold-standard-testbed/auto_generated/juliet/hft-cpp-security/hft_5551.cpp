// Vulnerable: HFT-5551
wchar_t * data;
wchar_t * *dataPtr1 = &data;
wchar_t * *dataPtr2 = &data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
wchar_t * data = *dataPtr1;
WSADATA wsaData;
int wsaDataInit = 0;
int recvResult;
struct sockaddr_in service;
...
wchar_t * data = *dataPtr2;
fwprintf(stdout, data);
