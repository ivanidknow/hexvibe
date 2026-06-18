// Vulnerable: HFT-9175
int data;
data = -1;
if(GLOBAL_CONST_FIVE==5)
data = RAND32();
if(GLOBAL_CONST_FIVE==5)
int buffer[10] = { 0 };
if (data >= 0)
printIntLine(buffer[data]);
else
printLine("ERROR: Array index is negative");
