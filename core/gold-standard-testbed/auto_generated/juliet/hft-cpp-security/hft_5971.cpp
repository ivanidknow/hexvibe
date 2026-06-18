// Vulnerable: HFT-5971
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
CWE15_External_Control_of_System_or_Configuration_Setting__w32_45_badData = data;
badSink();
