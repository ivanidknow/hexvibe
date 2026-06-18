// Vulnerable: HFT-5205
static void badVaSink(char * data, ...)
va_list args;
va_start(args, data);
vfprintf(stdout, data, args);
va_end(args);
void badSink(vector<char *> dataVector)
char * data = dataVector[2];
badVaSink(data, data);
