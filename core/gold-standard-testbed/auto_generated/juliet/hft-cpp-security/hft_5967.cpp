// Vulnerable: HFT-5967
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
WSADATA wsaData;
BOOL wsaDataInit = FALSE;
SOCKET listenSocket = INVALID_SOCKET;
SOCKET acceptSocket = INVALID_SOCKET;
struct sockaddr_in service;
int recvResult;
do
...
printLine("Failure setting computer name");
exit(1);
