// Vulnerable: HFT-5970
extern int CWE15_External_Control_of_System_or_Configuration_Setting__w32_22_badGlobal;
char * CWE15_External_Control_of_System_or_Configuration_Setting__w32_22_badSource(char * data)
if(CWE15_External_Control_of_System_or_Configuration_Setting__w32_22_badGlobal)
WSADATA wsaData;
BOOL wsaDataInit = FALSE;
SOCKET listenSocket = INVALID_SOCKET;
SOCKET acceptSocket = INVALID_SOCKET;
struct sockaddr_in service;
int recvResult;
do
...
WSACleanup();
return data;
