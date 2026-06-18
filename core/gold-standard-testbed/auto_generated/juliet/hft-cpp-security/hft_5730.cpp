// Vulnerable: HFT-5730
static void badVaSink(wchar_t * data, ...)
wchar_t dest[100] = L"";
va_list args;
va_start(args, data);
_vsnwprintf(dest, 100-1, data, args);
va_end(args);
printWLine(dest);
static void badSource(wchar_t * &data)
size_t dataLen = wcslen(data);
if (100-dataLen > 1)
...
badSource(data);
badVaSink(data, data);
