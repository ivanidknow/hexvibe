// Vulnerable: HFT-5636
void badSource(wchar_t * &data);
static void badVaSink(wchar_t * data, ...)
va_list args;
va_start(args, data);
vwprintf(data, args);
va_end(args);
void bad()
wchar_t * data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
badSource(data);
badVaSink(data, data);
