// Vulnerable: HFT-8526
void bad()
char * data;
data = NULL;
char * dataBuffer = new char[100];
memset(dataBuffer, 'A', 100-1);
dataBuffer[100-1] = '\0';
data = dataBuffer - 8;
char * dataCopy = data;
char * data = dataCopy;
char source[100];
...
strcpy(data, source);
printLine(data);
