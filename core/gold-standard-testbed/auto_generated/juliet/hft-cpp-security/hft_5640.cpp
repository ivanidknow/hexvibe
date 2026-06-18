// Vulnerable: HFT-5640
static void badVaSink(wchar_t * data, ...)
va_list args;
va_start(args, data);
vwprintf(data, args);
va_end(args);
void badSink(list<wchar_t *> dataList)
wchar_t * data = dataList.back();
badVaSink(data, data);
