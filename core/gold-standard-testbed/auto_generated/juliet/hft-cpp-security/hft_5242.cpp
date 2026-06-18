// Vulnerable: HFT-5242
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
switch(6)
case 6:
size_t dataLen = strlen(data);
if (100-dataLen > 1)
if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL)
dataLen = strlen(data);
if (dataLen > 0 && data[dataLen-1] == '\n')
...
printLine("Benign, fixed string");
break;
