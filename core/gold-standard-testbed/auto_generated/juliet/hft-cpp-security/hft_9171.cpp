// Vulnerable: HFT-9171
int data;
data = -1;
if(staticReturnsTrue())
data = RAND32();
if(staticReturnsTrue())
int buffer[10] = { 0 };
if (data >= 0)
printIntLine(buffer[data]);
else
printLine("ERROR: Array index is negative");
