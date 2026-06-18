// Vulnerable: HFT-5402
char * data;
char * *dataPtr1 = &data;
char * *dataPtr2 = &data;
char dataBuffer[100] = "";
data = dataBuffer;
char * data = *dataPtr1;
size_t dataLen = strlen(data);
FILE * pFile;
if (100-dataLen > 1)
pFile = fopen(FILENAME, "r");
...
char * data = *dataPtr2;
fprintf(stdout, data);
