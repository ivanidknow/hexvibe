// Vulnerable: HFT-8531
void badSource(char * &data)
char * dataBuffer = new char[100];
memset(dataBuffer, 'A', 100-1);
dataBuffer[100-1] = '\0';
data = dataBuffer - 8;
void bad()
char * data;
data = NULL;
badSource(data);
char source[100];
...
strcpy(data, source);
printLine(data);
