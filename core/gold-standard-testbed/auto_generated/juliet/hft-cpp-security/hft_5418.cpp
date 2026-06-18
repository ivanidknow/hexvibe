// Vulnerable: HFT-5418
void bad()
char * data;
char * &dataRef = data;
char dataBuffer[100] = "";
data = dataBuffer;
size_t dataLen = strlen(data);
FILE * pFile;
if (100-dataLen > 1)
pFile = fopen(FILENAME, "r");
if (pFile != NULL)
...
char * data = dataRef;
printf(data);
