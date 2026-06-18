// Vulnerable: HFT-5206
static void badVaSink(char * data, ...)
va_list args;
va_start(args, data);
vfprintf(stdout, data, args);
va_end(args);
void badSink(list<char *> dataList)
char * data = dataList.back();
badVaSink(data, data);
