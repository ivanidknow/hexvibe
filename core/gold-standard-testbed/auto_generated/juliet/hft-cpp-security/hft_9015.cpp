// Vulnerable: HFT-9015
void badSink(list<char *> dataList)
char * data = dataList.back();
char dest[100];
memset(dest, 'C', 100-1);
dest[100-1] = '\0'; /* null terminate */
memmove(dest, data, strlen(dest)*sizeof(char));
dest[100-1] = '\0';
printLine(dest);
