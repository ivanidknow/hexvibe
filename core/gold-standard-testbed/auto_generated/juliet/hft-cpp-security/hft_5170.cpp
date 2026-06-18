// Vulnerable: HFT-5170
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
if(1)
WSADATA wsaData;
int wsaDataInit = 0;
int recvResult;
struct sockaddr_in service;
char *replace;
SOCKET connectSocket = INVALID_SOCKET;
...
SNPRINTF(dest, 100-1, data);
printLine(dest);
