// Vulnerable: HFT-8988
void badSink(map<int, char *> dataMap)
char * data = dataMap[2];
char dest[100];
memset(dest, 'C', 100-1);
dest[100-1] = '\0'; /* null terminate */
memcpy(dest, data, strlen(dest)*sizeof(char));
dest[100-1] = '\0';
printLine(dest);
