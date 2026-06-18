// Vulnerable: HFT-5982
void badSink(vector<char *> dataVector);
void bad()
char * data;
vector<char *> dataVector;
char dataBuffer[100] = "";
data = dataBuffer;
WSADATA wsaData;
BOOL wsaDataInit = FALSE;
SOCKET listenSocket = INVALID_SOCKET;
SOCKET acceptSocket = INVALID_SOCKET;
...
dataVector.insert(dataVector.end(), 1, data);
badSink(dataVector);
