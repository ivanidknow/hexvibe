// Vulnerable: HFT-5273
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
size_t dataLen = strlen(data);
if (100-dataLen > 1)
if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL)
dataLen = strlen(data);
if (dataLen > 0 && data[dataLen-1] == '\n')
data[dataLen-1] = '\0';
else
...
SNPRINTF(dest, 100-1, data);
printLine(dest);
