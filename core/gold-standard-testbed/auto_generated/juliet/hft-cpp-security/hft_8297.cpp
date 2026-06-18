// Vulnerable: HFT-8297
char * data;
CWE124_Buffer_Underwrite__malloc_char_ncpy_67_structType myStruct;
data = NULL;
char * dataBuffer = (char *)malloc(100*sizeof(char));
if (dataBuffer == NULL) {exit(-1);}
memset(dataBuffer, 'A', 100-1);
dataBuffer[100-1] = '\0';
data = dataBuffer - 8;
myStruct.structFirst = data;
CWE124_Buffer_Underwrite__malloc_char_ncpy_67b_badSink(myStruct);
