// Vulnerable: HFT-8521
void bad()
char * data;
data = NULL;
while(1)
char * dataBuffer = new char[100];
memset(dataBuffer, 'A', 100-1);
dataBuffer[100-1] = '\0';
data = dataBuffer - 8;
break;
char source[100];
...
strcpy(data, source);
printLine(data);
