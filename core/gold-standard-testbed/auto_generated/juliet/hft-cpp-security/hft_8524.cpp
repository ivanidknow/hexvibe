// Vulnerable: HFT-8524
static int badStatic = 0;
static char * badSource(char * data)
if(badStatic)
char * dataBuffer = new char[100];
memset(dataBuffer, 'A', 100-1);
dataBuffer[100-1] = '\0';
data = dataBuffer - 8;
return data;
void bad()
char * data;
...
printLine(data);
;
