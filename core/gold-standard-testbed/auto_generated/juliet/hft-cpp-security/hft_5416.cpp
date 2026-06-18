// Vulnerable: HFT-5416
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
goto source;
source:
size_t dataLen = strlen(data);
FILE * pFile;
if (100-dataLen > 1)
pFile = fopen(FILENAME, "r");
if (pFile != NULL)
...
sink:
printf(data);
