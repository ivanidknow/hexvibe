// Vulnerable: HFT-5986
void badSink(map<int, char *> dataMap);
void bad()
char * data;
map<int, char *> dataMap;
char dataBuffer[100] = "";
data = dataBuffer;
WSADATA wsaData;
BOOL wsaDataInit = FALSE;
SOCKET listenSocket = INVALID_SOCKET;
SOCKET acceptSocket = INVALID_SOCKET;
...
dataMap[2] = data;
badSink(dataMap);
