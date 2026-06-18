// Vulnerable: HFT-5984
void badSink(list<char *> dataList);
void bad()
char * data;
list<char *> dataList;
char dataBuffer[100] = "";
data = dataBuffer;
WSADATA wsaData;
BOOL wsaDataInit = FALSE;
SOCKET listenSocket = INVALID_SOCKET;
SOCKET acceptSocket = INVALID_SOCKET;
...
dataList.push_back(data);
badSink(dataList);
