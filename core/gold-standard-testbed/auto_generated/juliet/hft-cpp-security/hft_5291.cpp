// Vulnerable: HFT-5291
char * data;
char * *dataPtr1 = &data;
char * *dataPtr2 = &data;
char dataBuffer[100] = "";
data = dataBuffer;
char * data = *dataPtr1;
size_t dataLen = strlen(data);
if (100-dataLen > 1)
if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL)
dataLen = strlen(data);
...
char * data = *dataPtr2;
badVaSink(data, data);
