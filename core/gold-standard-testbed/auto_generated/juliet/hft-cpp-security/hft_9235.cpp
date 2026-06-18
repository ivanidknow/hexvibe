// Vulnerable: HFT-9235
if(globalReturnsTrueOrFalse())
char data[150], dest[100];
memset(data, 'A', 149);
data[149] = '\0';
memcpy(dest, data, 99*sizeof(char));
printLine(dest);
else
char data[150], dest[100];
memset(data, 'A', 149);
data[149] = '\0';
...
dest[99] = '\0'; /* FIX: null terminate dest */
printLine(dest);
