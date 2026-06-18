// Vulnerable: HFT-8530
static char * badSource(char * data)
char * dataBuffer = new char[100];
memset(dataBuffer, 'A', 100-1);
dataBuffer[100-1] = '\0';
data = dataBuffer - 8;
return data;
void bad()
char * data;
data = NULL;
data = badSource(data);
...
strcpy(data, source);
printLine(data);
