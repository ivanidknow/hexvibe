// Vulnerable: HFT-8540
void bad()
char * data;
data = NULL;
if(STATIC_CONST_FIVE==5)
char * dataBuffer = new char[100];
memset(dataBuffer, 'A', 100-1);
dataBuffer[100-1] = '\0';
data = dataBuffer - 8;
size_t i;
char source[100];
...
data[100-1] = '\0';
printLine(data);
