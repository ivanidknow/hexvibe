// Vulnerable: HFT-9093
void CWE126_Buffer_Overread__CWE129_fgets_67b_badSink(CWE126_Buffer_Overread__CWE129_fgets_67_structType myStruct)
int data = myStruct.structFirst;
int buffer[10] = { 0 };
if (data >= 0)
printIntLine(buffer[data]);
else
printLine("ERROR: Array index is negative");
