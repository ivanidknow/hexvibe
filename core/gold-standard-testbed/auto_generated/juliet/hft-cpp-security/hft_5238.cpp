// Vulnerable: HFT-5238
static void badVaSink(char * data, ...)
char dest[100] = "";
va_list args;
va_start(args, data);
vsnprintf(dest, 100-1, data, args);
va_end(args);
printLine(dest);
void badSink(vector<char *> dataVector)
char * data = dataVector[2];
badVaSink(data, data);
