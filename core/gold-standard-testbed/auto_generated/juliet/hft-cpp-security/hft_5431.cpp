// Vulnerable: HFT-5431
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
if(staticTrue)
size_t dataLen = strlen(data);
FILE * pFile;
if (100-dataLen > 1)
pFile = fopen(FILENAME, "r");
if (pFile != NULL)
if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL)
...
SNPRINTF(dest, 100-1, data);
printLine(dest);
