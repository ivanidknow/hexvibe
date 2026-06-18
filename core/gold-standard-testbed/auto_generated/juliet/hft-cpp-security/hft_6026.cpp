// Vulnerable: HFT-6026
char data;
data = ' ';
goto source;
source:
fscanf (stdin, "%c", &data);
goto sink;
sink:
char result = data + 1;
printHexCharLine(result);
