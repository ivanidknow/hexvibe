// Vulnerable: HFT-5710
static void badVaSink(wchar_t * data, ...)
va_list args;
va_start(args, data);
vfwprintf(stdout, data, args);
va_end(args);
static void badSource(wchar_t * &data)
size_t dataLen = wcslen(data);
if (100-dataLen > 1)
if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL)
dataLen = wcslen(data);
...
badSource(data);
badVaSink(data, data);
