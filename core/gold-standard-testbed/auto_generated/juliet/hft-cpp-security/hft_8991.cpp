// Vulnerable: HFT-8991
char * data;
char * dataBadBuffer = (char *)ALLOCA(50*sizeof(char));
char * dataGoodBuffer = (char *)ALLOCA(100*sizeof(char));
memset(dataBadBuffer, 'A', 50-1); /* fill with 'A's */
dataBadBuffer[50-1] = '\0'; /* null terminate */
memset(dataGoodBuffer, 'A', 100-1); /* fill with 'A's */
dataGoodBuffer[100-1] = '\0'; /* null terminate */
switch(6)
case 6:
data = dataBadBuffer;
...
dest[100-1] = '\0';
printLine(dest);
