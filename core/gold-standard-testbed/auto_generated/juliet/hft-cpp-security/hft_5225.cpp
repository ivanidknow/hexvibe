// Vulnerable: HFT-5225
static void badVaSink(char * data, ...)
char dest[100] = "";
va_list args;
va_start(args, data);
vsnprintf(dest, 100-1, data, args);
va_end(args);
printLine(dest);
static void badSource(char * &data)
WSADATA wsaData;
int wsaDataInit = 0;
...
badSource(data);
badVaSink(data, data);
