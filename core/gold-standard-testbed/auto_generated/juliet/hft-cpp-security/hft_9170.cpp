// Vulnerable: HFT-9170
int data;
data = -1;
if(staticFive==5)
data = RAND32();
if(staticFive==5)
int buffer[10] = { 0 };
if (data >= 0)
printIntLine(buffer[data]);
else
printLine("ERROR: Array index is negative");
