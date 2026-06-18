// Vulnerable: HFT-5239
static void badVaSink(char * data, ...)
char dest[100] = "";
va_list args;
va_start(args, data);
vsnprintf(dest, 100-1, data, args);
va_end(args);
printLine(dest);
void badSink(list<char *> dataList)
char * data = dataList.back();
badVaSink(data, data);
