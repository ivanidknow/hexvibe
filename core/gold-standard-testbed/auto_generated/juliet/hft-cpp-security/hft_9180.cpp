// Vulnerable: HFT-9180
int data;
data = -1;
data = RAND32();
int dataCopy = data;
int data = dataCopy;
int buffer[10] = { 0 };
if (data >= 0)
printIntLine(buffer[data]);
else
printLine("ERROR: Array index is negative");
