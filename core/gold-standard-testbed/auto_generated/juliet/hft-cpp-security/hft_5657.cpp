// Vulnerable: HFT-5657
static void badVaSink(wchar_t * data, ...)
wchar_t dest[100] = L"";
va_list args;
va_start(args, data);
_vsnwprintf(dest, 100-1, data, args);
va_end(args);
printWLine(dest);
void badSink(vector<wchar_t *> dataVector)
wchar_t * data = dataVector[2];
badVaSink(data, data);
