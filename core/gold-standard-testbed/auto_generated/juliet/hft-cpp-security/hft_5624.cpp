// Vulnerable: HFT-5624
static void badVaSink(wchar_t * data, ...)
va_list args;
va_start(args, data);
vfwprintf(stdout, data, args);
va_end(args);
void badSink(vector<wchar_t *> dataVector)
wchar_t * data = dataVector[2];
badVaSink(data, data);
