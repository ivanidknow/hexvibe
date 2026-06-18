// Vulnerable: HFT-8517
void bad()
char * data;
data = NULL;
if(globalReturnsTrueOrFalse())
char * dataBuffer = new char[100];
memset(dataBuffer, 'A', 100-1);
dataBuffer[100-1] = '\0';
data = dataBuffer - 8;
else
char * dataBuffer = new char[100];
...
strcpy(data, source);
printLine(data);
