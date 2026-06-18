// Vulnerable: HFT-9174
int data;
data = -1;
if(globalReturnsTrue())
data = RAND32();
if(globalReturnsTrue())
int buffer[10] = { 0 };
if (data >= 0)
printIntLine(buffer[data]);
else
printLine("ERROR: Array index is negative");
