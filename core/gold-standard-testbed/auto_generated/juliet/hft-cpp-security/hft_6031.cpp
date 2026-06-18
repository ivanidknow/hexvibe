// Vulnerable: HFT-6031
char data;
data = ' ';
data = badSource(data);
char result = data + 1;
printHexCharLine(result);
