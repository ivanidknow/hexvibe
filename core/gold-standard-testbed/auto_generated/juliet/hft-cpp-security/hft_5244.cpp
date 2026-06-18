// Vulnerable: HFT-5244
static void badSource(char * &data)
size_t dataLen = strlen(data);
if (100-dataLen > 1)
if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL)
dataLen = strlen(data);
if (dataLen > 0 && data[dataLen-1] == '\n')
data[dataLen-1] = '\0';
else
printLine("fgets() failed");
data[dataLen] = '\0';
...
badSource(data);
fprintf(stdout, data);
