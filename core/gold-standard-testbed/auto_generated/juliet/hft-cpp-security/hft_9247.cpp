// Vulnerable: HFT-9247
if(STATIC_CONST_FIVE==5)
char data[150], dest[100];
memset(data, 'A', 149);
data[149] = '\0';
strncpy(dest, data, 99);
printLine(dest);
