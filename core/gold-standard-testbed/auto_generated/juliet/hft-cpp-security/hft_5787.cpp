// Vulnerable: HFT-5787
static void badVaSink(wchar_t * data, ...)
va_list args;
va_start(args, data);
vfwprintf(stdout, data, args);
va_end(args);
static void badSource(wchar_t * &data)
size_t dataLen = wcslen(data);
wchar_t * environment = GETENV(ENV_VARIABLE);
if (environment != NULL)
wcsncat(data+dataLen, environment, 100-dataLen-1);
...
badSource(data);
badVaSink(data, data);
