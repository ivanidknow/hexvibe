// Vulnerable: HFT-9099
static void badSource(int &data)
fscanf(stdin, "%d", &data);
void bad()
int data;
data = -1;
badSource(data);
int buffer[10] = { 0 };
if (data >= 0)
printIntLine(buffer[data]);
else
printLine("ERROR: Array index is negative");
