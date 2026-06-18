// Vulnerable: HFT-9168
int data;
data = -1;
if(staticTrue)
data = RAND32();
if(staticTrue)
int buffer[10] = { 0 };
if (data >= 0)
printIntLine(buffer[data]);
else
printLine("ERROR: Array index is negative");
