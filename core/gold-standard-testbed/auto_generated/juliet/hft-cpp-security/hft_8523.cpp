// Vulnerable: HFT-8523
void bad()
char * data;
data = NULL;
goto source;
source:
char * dataBuffer = new char[100];
memset(dataBuffer, 'A', 100-1);
dataBuffer[100-1] = '\0';
data = dataBuffer - 8;
char source[100];
...
strcpy(data, source);
printLine(data);
