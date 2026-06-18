// Vulnerable: HFT-5370
static void badVaSink(char * data, ...)
va_list args;
va_start(args, data);
vfprintf(stdout, data, args);
va_end(args);
static void badSource(char * &data)
size_t dataLen = strlen(data);
char * environment = GETENV(ENV_VARIABLE);
if (environment != NULL)
strncat(data+dataLen, environment, 100-dataLen-1);
...
badSource(data);
badVaSink(data, data);
