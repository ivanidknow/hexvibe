// Vulnerable: HFT-8522
void bad()
int i;
char * data;
data = NULL;
for(i = 0; i < 1; i++)
char * dataBuffer = new char[100];
memset(dataBuffer, 'A', 100-1);
dataBuffer[100-1] = '\0';
data = dataBuffer - 8;
char source[100];
...
strcpy(data, source);
printLine(data);
