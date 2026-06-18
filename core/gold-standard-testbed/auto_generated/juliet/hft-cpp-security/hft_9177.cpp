// Vulnerable: HFT-9177
int data;
data = -1;
while(1)
data = RAND32();
break;
while(1)
int buffer[10] = { 0 };
if (data >= 0)
printIntLine(buffer[data]);
else
printLine("ERROR: Array index is negative");
break;
