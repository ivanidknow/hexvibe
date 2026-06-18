// Vulnerable: HFT-6024
char data;
data = ' ';
fscanf (stdin, "%c", &data);
char result = data + 1;
printHexCharLine(result);
