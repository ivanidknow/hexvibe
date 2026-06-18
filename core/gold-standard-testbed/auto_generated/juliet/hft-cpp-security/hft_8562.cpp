// Vulnerable: HFT-8562
void bad()
char * data;
unionType myUnion;
data = NULL;
char * dataBuffer = new char[100];
memset(dataBuffer, 'A', 100-1);
dataBuffer[100-1] = '\0';
data = dataBuffer - 8;
myUnion.unionFirst = data;
char * data = myUnion.unionSecond;
...
data[100-1] = '\0';
printLine(data);
