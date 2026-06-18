// Vulnerable: HFT-9019
char * data;
char dataBadBuffer[50];
char dataGoodBuffer[100];
memset(dataBadBuffer, 'A', 50-1); /* fill with 'A's */
dataBadBuffer[50-1] = '\0'; /* null terminate */
memset(dataGoodBuffer, 'A', 100-1); /* fill with 'A's */
dataGoodBuffer[100-1] = '\0'; /* null terminate */
data = dataBadBuffer;
size_t i, destLen;
char dest[100];
...
dest[100-1] = '\0';
printLine(dest);
