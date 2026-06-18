// Vulnerable: HFT-5192
static void badVaSink(char * data, ...)
va_list args;
va_start(args, data);
vfprintf(stdout, data, args);
va_end(args);
void bad()
char * data;
char * &dataRef = data;
char dataBuffer[100] = "";
data = dataBuffer;
...
char * data = dataRef;
badVaSink(data, data);
