// Vulnerable: HFT-5400
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
switch(6)
case 6:
size_t dataLen = strlen(data);
FILE * pFile;
if (100-dataLen > 1)
pFile = fopen(FILENAME, "r");
if (pFile != NULL)
...
printLine("Benign, fixed string");
break;
