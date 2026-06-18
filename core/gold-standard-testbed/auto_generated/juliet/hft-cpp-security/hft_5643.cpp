// Vulnerable: HFT-5643
static void badVaSink(wchar_t * data, ...)
wchar_t dest[100] = L"";
va_list args;
va_start(args, data);
_vsnwprintf(dest, 100-1, data, args);
va_end(args);
printWLine(dest);
void bad()
wchar_t * data;
wchar_t * &dataRef = data;
...
wchar_t * data = dataRef;
badVaSink(data, data);
