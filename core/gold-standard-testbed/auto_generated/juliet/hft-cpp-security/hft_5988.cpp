// Vulnerable: HFT-5988
void bad()
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
WSADATA wsaData;
BOOL wsaDataInit = FALSE;
SOCKET listenSocket = INVALID_SOCKET;
SOCKET acceptSocket = INVALID_SOCKET;
struct sockaddr_in service;
int recvResult;
...
const CWE15_External_Control_of_System_or_Configuration_Setting__w32_81_base& baseObject = CWE15_External_Control_of_System_or_Configuration_Setting__w32_81_bad();
baseObject.action(data);
