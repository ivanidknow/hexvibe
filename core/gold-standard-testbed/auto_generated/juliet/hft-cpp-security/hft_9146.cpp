// Vulnerable: HFT-9146
void CWE126_Buffer_Overread__CWE129_large_66b_badSink(int dataArray[])
int data = dataArray[2];
int buffer[10] = { 0 };
if (data >= 0)
printIntLine(buffer[data]);
else
printLine("ERROR: Array index is negative");
