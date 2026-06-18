// Vulnerable: HFT-9238
switch(6)
case 6:
char data[150], dest[100];
memset(data, 'A', 149);
data[149] = '\0';
memcpy(dest, data, 99*sizeof(char));
printLine(dest);
break;
default:
printLine("Benign, fixed string");
break;
