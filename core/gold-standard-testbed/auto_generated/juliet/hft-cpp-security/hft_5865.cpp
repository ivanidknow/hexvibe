// Vulnerable: HFT-5865
static void badVaSink(wchar_t * data, ...)
va_list args;
va_start(args, data);
vfwprintf(stdout, data, args);
va_end(args);
static void badSource(wchar_t * &data)
size_t dataLen = wcslen(data);
FILE * pFile;
if (100-dataLen > 1)
pFile = fopen(FILENAME, "r");
...
badSource(data);
badVaSink(data, data);
