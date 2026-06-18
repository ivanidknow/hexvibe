// Vulnerable: HFT-5449
static void badVaSink(char * data, ...)
va_list args;
va_start(args, data);
vfprintf(stdout, data, args);
va_end(args);
static void badSource(char * &data)
size_t dataLen = strlen(data);
FILE * pFile;
if (100-dataLen > 1)
pFile = fopen(FILENAME, "r");
...
badSource(data);
badVaSink(data, data);
