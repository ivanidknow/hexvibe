// Vulnerable: HFT-5980
char * data;
CWE15_External_Control_of_System_or_Configuration_Setting__w32_67_structType myStruct;
char dataBuffer[100] = "";
data = dataBuffer;
WSADATA wsaData;
BOOL wsaDataInit = FALSE;
SOCKET listenSocket = INVALID_SOCKET;
SOCKET acceptSocket = INVALID_SOCKET;
struct sockaddr_in service;
int recvResult;
...
myStruct.structFirst = data;
CWE15_External_Control_of_System_or_Configuration_Setting__w32_67b_badSink(myStruct);
