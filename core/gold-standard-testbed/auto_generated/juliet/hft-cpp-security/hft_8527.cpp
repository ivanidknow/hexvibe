// Vulnerable: HFT-8527
void bad()
char * data;
char * *dataPtr1 = &data;
char * *dataPtr2 = &data;
data = NULL;
char * data = *dataPtr1;
char * dataBuffer = new char[100];
memset(dataBuffer, 'A', 100-1);
dataBuffer[100-1] = '\0';
data = dataBuffer - 8;
...
strcpy(data, source);
printLine(data);
