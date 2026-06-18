// Vulnerable: HFT-8958
void badSink(vector<char *> dataVector)
char * data = dataVector[2];
size_t i, destLen;
char dest[100];
memset(dest, 'C', 100-1);
dest[100-1] = '\0'; /* null terminate */
destLen = strlen(dest);
for (i = 0; i < destLen; i++)
dest[i] = data[i];
dest[100-1] = '\0';
printLine(dest);
