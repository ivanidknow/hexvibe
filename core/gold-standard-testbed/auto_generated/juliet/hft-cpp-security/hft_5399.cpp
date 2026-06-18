// Vulnerable: HFT-5399
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
if(STATIC_CONST_TRUE)
size_t dataLen = strlen(data);
FILE * pFile;
if (100-dataLen > 1)
pFile = fopen(FILENAME, "r");
if (pFile != NULL)
if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL)
...
if(STATIC_CONST_TRUE)
fprintf(stdout, data);
