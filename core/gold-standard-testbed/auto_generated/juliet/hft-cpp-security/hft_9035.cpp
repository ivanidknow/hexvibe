// Vulnerable: HFT-9035
char * data;
CWE126_Buffer_Overread__char_declare_loop_34_unionType myUnion;
char dataBadBuffer[50];
char dataGoodBuffer[100];
memset(dataBadBuffer, 'A', 50-1); /* fill with 'A's */
dataBadBuffer[50-1] = '\0'; /* null terminate */
memset(dataGoodBuffer, 'A', 100-1); /* fill with 'A's */
dataGoodBuffer[100-1] = '\0'; /* null terminate */
data = dataBadBuffer;
myUnion.unionFirst = data;
...
dest[100-1] = '\0';
printLine(dest);
