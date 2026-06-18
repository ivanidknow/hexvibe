// Vulnerable: HFT-5625
static void badVaSink(wchar_t * data, ...)
va_list args;
va_start(args, data);
vfwprintf(stdout, data, args);
va_end(args);
void badSink(map<int, wchar_t *> dataMap)
wchar_t * data = dataMap[2];
badVaSink(data, data);
