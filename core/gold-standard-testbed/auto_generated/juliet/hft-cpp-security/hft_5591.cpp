// Vulnerable: HFT-5591
wchar_t * data;
CWE134_Uncontrolled_Format_String__wchar_t_connect_socket_snprintf_34_unionType myUnion;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
WSADATA wsaData;
int wsaDataInit = 0;
int recvResult;
struct sockaddr_in service;
wchar_t *replace;
SOCKET connectSocket = INVALID_SOCKET;
...
SNPRINTF(dest, 100-1, data);
printWLine(dest);
