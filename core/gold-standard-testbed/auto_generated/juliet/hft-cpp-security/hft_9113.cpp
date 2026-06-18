// Vulnerable: HFT-9113
void CWE126_Buffer_Overread__CWE129_fscanf_63b_badSink(int * dataPtr)
int data = *dataPtr;
int buffer[10] = { 0 };
if (data >= 0)
printIntLine(buffer[data]);
else
printLine("ERROR: Array index is negative");
