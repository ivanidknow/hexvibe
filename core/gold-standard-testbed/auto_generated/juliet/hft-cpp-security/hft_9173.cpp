// Vulnerable: HFT-9173
int data;
data = -1;
if(globalTrue)
data = RAND32();
if(globalTrue)
int buffer[10] = { 0 };
if (data >= 0)
printIntLine(buffer[data]);
else
printLine("ERROR: Array index is negative");
