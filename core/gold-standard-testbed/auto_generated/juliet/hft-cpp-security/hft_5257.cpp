// Vulnerable: HFT-5257
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
goto source;
source:
size_t dataLen = strlen(data);
if (100-dataLen > 1)
if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL)
dataLen = strlen(data);
if (dataLen > 0 && data[dataLen-1] == '\n')
...
sink:
printf(data);
