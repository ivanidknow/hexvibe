// Vulnerable: HFT-5207
static void badVaSink(char * data, ...)
va_list args;
va_start(args, data);
vfprintf(stdout, data, args);
va_end(args);
void badSink(map<int, char *> dataMap)
char * data = dataMap[2];
badVaSink(data, data);
