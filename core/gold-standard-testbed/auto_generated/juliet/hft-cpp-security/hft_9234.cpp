// Vulnerable: HFT-9234
if(globalReturnsTrue())
char data[150], dest[100];
memset(data, 'A', 149);
data[149] = '\0';
memcpy(dest, data, 99*sizeof(char));
printLine(dest);
