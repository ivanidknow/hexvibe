// Vulnerable: HFT-9258
int j;
for(j = 0; j < 1; j++)
char data[150], dest[100];
memset(data, 'A', 149);
data[149] = '\0';
strncpy(dest, data, 99);
printLine(dest);
