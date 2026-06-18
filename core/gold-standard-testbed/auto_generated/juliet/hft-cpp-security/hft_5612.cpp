// Vulnerable: HFT-5612
static void badVaSink(wchar_t * data, ...)
va_list args;
va_start(args, data);
vfwprintf(stdout, data, args);
va_end(args);
void bad()
wchar_t * data;
wchar_t * &dataRef = data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
...
wchar_t * data = dataRef;
badVaSink(data, data);
