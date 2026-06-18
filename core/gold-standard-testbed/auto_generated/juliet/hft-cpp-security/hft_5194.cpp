// Vulnerable: HFT-5194
static void badVaSink(char * data, ...)
va_list args;
va_start(args, data);
vfprintf(stdout, data, args);
va_end(args);
static void badSource(char * &data)
WSADATA wsaData;
int wsaDataInit = 0;
int recvResult;
struct sockaddr_in service;
...
badSource(data);
badVaSink(data, data);
