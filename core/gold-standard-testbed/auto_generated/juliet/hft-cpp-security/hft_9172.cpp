// Vulnerable: HFT-9172
int data;
data = -1;
if(GLOBAL_CONST_TRUE)
data = RAND32();
if(GLOBAL_CONST_TRUE)
int buffer[10] = { 0 };
if (data >= 0)
printIntLine(buffer[data]);
else
printLine("ERROR: Array index is negative");
