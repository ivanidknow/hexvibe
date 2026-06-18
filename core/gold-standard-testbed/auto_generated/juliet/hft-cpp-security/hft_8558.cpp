// Vulnerable: HFT-8558
static void badSink(char * data)
char source[100];
memset(source, 'C', 100-1); /* fill with 'C's */
source[100-1] = '\0'; /* null terminate */
memmove(data, source, 100*sizeof(char));
data[100-1] = '\0';
printLine(data);
void bad()
char * data;
void (*funcPtr) (char *) = badSink;
...
data = dataBuffer - 8;
funcPtr(data);
