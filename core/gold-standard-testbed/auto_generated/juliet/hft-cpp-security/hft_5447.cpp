// Vulnerable: HFT-5447
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
while(1)
size_t dataLen = strlen(data);
FILE * pFile;
if (100-dataLen > 1)
pFile = fopen(FILENAME, "r");
if (pFile != NULL)
if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL)
...
badVaSinkB(data, data);
break;
