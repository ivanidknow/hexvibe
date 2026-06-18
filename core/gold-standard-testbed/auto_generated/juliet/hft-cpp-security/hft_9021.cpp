// Vulnerable: HFT-9021
char * data;
char dataBadBuffer[50];
char dataGoodBuffer[100];
memset(dataBadBuffer, 'A', 50-1); /* fill with 'A's */
dataBadBuffer[50-1] = '\0'; /* null terminate */
memset(dataGoodBuffer, 'A', 100-1); /* fill with 'A's */
dataGoodBuffer[100-1] = '\0'; /* null terminate */
if(5==5)
data = dataBadBuffer;
size_t i, destLen;
...
dest[100-1] = '\0';
printLine(dest);
