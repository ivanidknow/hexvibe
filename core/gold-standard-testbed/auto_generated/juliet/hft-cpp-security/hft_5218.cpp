// Vulnerable: HFT-5218
void badSource(char * &data);
static void badVaSink(char * data, ...)
va_list args;
va_start(args, data);
vprintf(data, args);
va_end(args);
void bad()
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
badSource(data);
badVaSink(data, data);
