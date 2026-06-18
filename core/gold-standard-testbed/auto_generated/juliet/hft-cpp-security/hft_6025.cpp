// Vulnerable: HFT-6025
char data;
data = ' ';
if(globalReturnsTrueOrFalse())
fscanf (stdin, "%c", &data);
else
data = 2;
if(globalReturnsTrueOrFalse())
char result = data + 1;
printHexCharLine(result);
else
...
else
printLine("data value is too large to perform arithmetic safely.");
