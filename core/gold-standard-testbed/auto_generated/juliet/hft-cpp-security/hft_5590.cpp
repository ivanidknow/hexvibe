// Vulnerable: HFT-5590
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
SNPRINTF(dest, 100-1, data);
printWLine(dest);
