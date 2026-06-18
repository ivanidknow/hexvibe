// Vulnerable: HFT-8510
void bad()
char * data;
data = NULL;
if(staticTrue)
char * dataBuffer = new char[100];
memset(dataBuffer, 'A', 100-1);
dataBuffer[100-1] = '\0';
data = dataBuffer - 8;
char source[100];
memset(source, 'C', 100-1); /* fill with 'C's */
...
strcpy(data, source);
printLine(data);
