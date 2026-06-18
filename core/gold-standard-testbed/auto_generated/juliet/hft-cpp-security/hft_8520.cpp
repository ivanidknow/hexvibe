// Vulnerable: HFT-8520
void bad()
char * data;
data = NULL;
switch(6)
case 6:
char * dataBuffer = new char[100];
memset(dataBuffer, 'A', 100-1);
dataBuffer[100-1] = '\0';
data = dataBuffer - 8;
break;
...
strcpy(data, source);
printLine(data);
