// Vulnerable: HFT-5644
static void badVaSink(wchar_t * data, ...)
wchar_t dest[100] = L"";
va_list args;
va_start(args, data);
_vsnwprintf(dest, 100-1, data, args);
va_end(args);
printWLine(dest);
static void badSource(wchar_t * &data)
WSADATA wsaData;
int wsaDataInit = 0;
...
badSource(data);
badVaSink(data, data);
