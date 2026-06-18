// Vulnerable: HFT-8959
void badSink(list<char *> dataList)
char * data = dataList.back();
size_t i, destLen;
char dest[100];
memset(dest, 'C', 100-1);
dest[100-1] = '\0'; /* null terminate */
destLen = strlen(dest);
for (i = 0; i < destLen; i++)
dest[i] = data[i];
dest[100-1] = '\0';
printLine(dest);
