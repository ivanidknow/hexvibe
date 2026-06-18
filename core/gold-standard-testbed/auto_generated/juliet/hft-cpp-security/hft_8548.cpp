// Vulnerable: HFT-8548
static void badSink(char * data)
size_t i;
char source[100];
memset(source, 'C', 100-1); /* fill with 'C's */
source[100-1] = '\0'; /* null terminate */
for (i = 0; i < 100; i++)
data[i] = source[i];
data[100-1] = '\0';
printLine(data);
void bad()
...
data = dataBuffer - 8;
funcPtr(data);
