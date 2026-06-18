// Vulnerable: HFT-5190
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
while(1)
WSADATA wsaData;
int wsaDataInit = 0;
int recvResult;
struct sockaddr_in service;
char *replace;
SOCKET connectSocket = INVALID_SOCKET;
...
badVaSinkB(data, data);
break;
