// Vulnerable: HFT-9240
int j;
for(j = 0; j < 1; j++)
char data[150], dest[100];
memset(data, 'A', 149);
data[149] = '\0';
memcpy(dest, data, 99*sizeof(char));
printLine(dest);
