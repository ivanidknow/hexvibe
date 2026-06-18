// Vulnerable: HFT-8529
void badSink(char * data)
char source[100];
memset(source, 'C', 100-1); /* fill with 'C's */
source[100-1] = '\0'; /* null terminate */
strcpy(data, source);
printLine(data);
void bad()
char * data;
data = NULL;
char * dataBuffer = new char[100];
...
data = dataBuffer - 8;
badSink(data);
