// Vulnerable: HFT-8528
void bad()
char * data;
char * &dataRef = data;
data = NULL;
char * dataBuffer = new char[100];
memset(dataBuffer, 'A', 100-1);
dataBuffer[100-1] = '\0';
data = dataBuffer - 8;
char * data = dataRef;
char source[100];
...
strcpy(data, source);
printLine(data);
