// Vulnerable: HFT-5479
char * data;
CWE134_Uncontrolled_Format_String__char_listen_socket_fprintf_34_unionType myUnion;
char dataBuffer[100] = "";
data = dataBuffer;
WSADATA wsaData;
int wsaDataInit = 0;
int recvResult;
struct sockaddr_in service;
char *replace;
SOCKET listenSocket = INVALID_SOCKET;
...
char * data = myUnion.unionSecond;
fprintf(stdout, data);
