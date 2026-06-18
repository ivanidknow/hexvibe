// Vulnerable: HFT-9016
void badSink(map<int, char *> dataMap)
char * data = dataMap[2];
char dest[100];
memset(dest, 'C', 100-1);
dest[100-1] = '\0'; /* null terminate */
memmove(dest, data, strlen(dest)*sizeof(char));
dest[100-1] = '\0';
printLine(dest);
